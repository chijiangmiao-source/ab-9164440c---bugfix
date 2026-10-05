"""Core monitoring engine.

Invariants enforced here:

* Idempotent retransmission — ``event_id`` is the stable identity.  A
  retransmission with identical content replays the originally stored
  ack verbatim; identical id with different content is a conflict.
* Watermark honesty — a probe only contributes the max observed time of
  its *contiguous* sequence prefix (no gaps, starting at seq 1).  The
  watermark is ``min(frontier_alpha, frontier_beta) - allowed_lateness``
  and only exists once both probes have reported.  Sequence jumps,
  regressions, or an absent probe can never fabricate a watermark.
* Transactional sealing — a window is sealed (total, peak, level, first
  violation, both probes' progress) only when its end is not later than
  the watermark, and always inside the same persistent transaction as
  the reading that made it sealable.  ``window_start_ms`` is the primary
  key, so concurrent submissions and restarts leave exactly one record.
* Immutability — a reading whose observation falls into an already
  sealed window is rejected, contributes no dose, and never raises the
  probe frontier.  It is nevertheless recorded as a *tombstone*
  (``rejected_readings``): the sequence number is disposed of rather
  than left looking like an unfilled gap, so later valid readings (and
  a restart) can still extend the contiguous prefix and the watermark.
  Tombstones preserve idempotency/conflict semantics: the identical
  packet replays the same 409, the same ``event_id`` with different
  content is an ``event_conflict``, and reuse of the ``(probe, seq)``
  pair is a ``seq_conflict``.
"""
from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone

from .config import Settings
from .models import ReadingIn
from .storage import Storage

LEVELS = ("NORMAL", "ELEVATED", "CRITICAL")


class ConflictError(Exception):
    """Raised for 409-class rejections (event conflict, sealed window, seq reuse)."""

    def __init__(self, code: str, message: str, detail: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail or {}


class BadRequestError(Exception):
    """Raised for 400-class rejections (e.g. unknown probe)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def iso(ms: int | None) -> str | None:
    if ms is None:
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def to_ms(dt: datetime) -> int:
    return round(dt.timestamp() * 1000)


def _content_hash(reading: ReadingIn, observed_ms: int) -> str:
    payload = {
        "event_id": reading.event_id,
        "probe": reading.probe,
        "seq": reading.seq,
        "observed_at_ms": observed_ms,
        "dose": reading.dose,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


class Engine:
    def __init__(self, storage: Storage, settings: Settings):
        self.storage = storage
        self.settings = settings

    # ------------------------------------------------------------------ ingest

    def submit(self, reading: ReadingIn) -> tuple[dict, bool]:
        """Ingest one reading.  Returns ``(ack, replayed)``.

        Raises :class:`BadRequestError` for an unknown probe and
        :class:`ConflictError` for event conflicts, sequence reuse, or
        data landing in an already sealed window.

        A ``window_sealed`` rejection is itself persisted as a tombstone
        (in the same transaction) *before* the 409 is raised, so the
        rejected sequence is durably disposed of: it neither aggregates
        dose nor advances the frontier, yet it no longer looks like an
        unfilled gap to later readings.
        """
        s = self.settings
        if reading.probe not in s.probes:
            raise BadRequestError(
                "unknown_probe",
                f"probe {reading.probe!r} is not configured; expected one of {sorted(s.probes)}",
            )
        observed_ms = to_ms(reading.observed_at)
        content_hash = _content_hash(reading, observed_ms)
        window_start = (observed_ms // s.window_ms) * s.window_ms
        now_ms = round(time.time() * 1000)

        # Raised only after the write transaction commits (a persisted
        # rejection must survive the 409 it answers with).
        pending: ConflictError | None = None

        with self.storage.write_txn() as conn:
            row = conn.execute(
                "SELECT * FROM readings WHERE event_id = ?", (reading.event_id,)
            ).fetchone()
            if row is not None:
                if row["content_hash"] == content_hash:
                    # Identical retransmission: replay the original ack verbatim.
                    return json.loads(row["ack_json"]), True
                raise ConflictError(
                    "event_conflict",
                    f"event_id {reading.event_id!r} already exists with different content",
                    detail={
                        "stored": {
                            "probe": row["probe"],
                            "seq": row["seq"],
                            "observed_at": iso(row["observed_at_ms"]),
                            "dose": row["dose"],
                        },
                        "received": {
                            "probe": reading.probe,
                            "seq": reading.seq,
                            "observed_at": iso(observed_ms),
                            "dose": reading.dose,
                        },
                    },
                )

            # A previously rejected packet is also a known identity: its
            # tombstone preserves the idempotency/conflict contract across
            # retransmission and restarts.
            tomb = conn.execute(
                "SELECT * FROM rejected_readings WHERE event_id = ?", (reading.event_id,)
            ).fetchone()
            if tomb is not None:
                if tomb["content_hash"] != content_hash:
                    raise ConflictError(
                        "event_conflict",
                        f"event_id {reading.event_id!r} already exists with different content",
                        detail={
                            "stored": {
                                "probe": tomb["probe"],
                                "seq": tomb["seq"],
                                "observed_at": iso(tomb["observed_at_ms"]),
                                "dose": tomb["dose"],
                            },
                            "received": {
                                "probe": reading.probe,
                                "seq": reading.seq,
                                "observed_at": iso(observed_ms),
                                "dose": reading.dose,
                            },
                        },
                    )
                # Identical replay of a rejected packet: the same 409,
                # verbatim, every time.
                pending = self._sealed_window_error(
                    s,
                    tomb["window_start_ms"],
                    tomb["reason"],
                    tomb["watermark_ms"],
                )
            else:
                seq_owner = conn.execute(
                    "SELECT event_id FROM readings WHERE probe = ? AND seq = ?"
                    " UNION ALL"
                    " SELECT event_id FROM rejected_readings WHERE probe = ? AND seq = ?",
                    (reading.probe, reading.seq, reading.probe, reading.seq),
                ).fetchone()
                if seq_owner is not None:
                    raise ConflictError(
                        "seq_conflict",
                        f"probe {reading.probe!r} seq {reading.seq} is already bound to "
                        f"event {seq_owner['event_id']!r}",
                    )

                reason = None
                sealed = conn.execute(
                    "SELECT 1 FROM windows WHERE window_start_ms = ?", (window_start,)
                ).fetchone()
                if sealed is not None:
                    reason = "sealed"
                    watermark_at_rejection = None
                else:
                    # Watermark gate: a window whose end is at or before the current
                    # watermark is closed even if no physical record exists for it
                    # (e.g. it predates the first observed event).  Late packets can
                    # never create or rewrite a published risk level.
                    current_wm = self._watermark(conn)
                    if current_wm is not None and window_start + s.window_ms <= current_wm:
                        reason = "past_watermark"
                        watermark_at_rejection = current_wm

                if reason is not None:
                    # Persist the disposition so this seq can never masquerade
                    # as an unfilled gap, then update progress in the same
                    # transaction.  No dose is stored and the frontier never
                    # rises, so no window seals and no summary changes.
                    conn.execute(
                        "INSERT INTO rejected_readings (event_id, probe, seq,"
                        " observed_at_ms, dose, content_hash, reason,"
                        " window_start_ms, watermark_ms, received_at_ms)"
                        " VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (
                            reading.event_id,
                            reading.probe,
                            reading.seq,
                            observed_ms,
                            reading.dose,
                            content_hash,
                            reason,
                            window_start,
                            watermark_at_rejection,
                            now_ms,
                        ),
                    )
                    self._advance_probe(conn, reading.probe, reading.seq, observed_ms, now_ms)
                    # The tombstone supplies no time itself, but it can close a
                    # gap and thereby reach accepted readings buffered beyond
                    # it, which may honestly raise the watermark; seal any
                    # windows that became sealable, in this same transaction.
                    self._seal_windows(conn, self._watermark(conn), now_ms)
                    pending = self._sealed_window_error(
                        s, window_start, reason, watermark_at_rejection
                    )
                else:
                    conn.execute(
                        "INSERT INTO readings (event_id, probe, seq, observed_at_ms, dose,"
                        " content_hash, ack_json, received_at_ms) VALUES (?,?,?,?,?,?,?,?)",
                        (
                            reading.event_id,
                            reading.probe,
                            reading.seq,
                            observed_ms,
                            reading.dose,
                            content_hash,
                            "{}",
                            now_ms,
                        ),
                    )

                    self._advance_probe(conn, reading.probe, reading.seq, observed_ms, now_ms)
                    watermark_ms = self._watermark(conn)
                    sealed_summaries = self._seal_windows(conn, watermark_ms, now_ms)
                    ack = {
                        "event_id": reading.event_id,
                        "probe": reading.probe,
                        "seq": reading.seq,
                        "status": "accepted",
                        "window_start": iso(window_start),
                        "window_end": iso(window_start + s.window_ms),
                        "watermark": iso(watermark_ms),
                        "sealed_windows": sealed_summaries,
                        "probe_progress": self._progress(conn),
                    }
                    # Persist the ack so identical retransmissions replay it exactly,
                    # even after a process restart.
                    conn.execute(
                        "UPDATE readings SET ack_json = ? WHERE event_id = ?",
                        (json.dumps(ack, sort_keys=True), reading.event_id),
                    )

        # The tombstone (and any progress bookkeeping) committed with the
        # transaction; only now do we answer with the rejection.
        if pending is not None:
            raise pending
        return ack, False

    @staticmethod
    def _sealed_window_error(
        s: Settings, window_start: int, reason: str, watermark_ms: int | None
    ) -> ConflictError:
        if reason == "sealed":
            return ConflictError(
                "window_sealed",
                f"window starting {iso(window_start)} is already sealed; "
                "late reading rejected without altering the published summary",
                detail={"window_start": iso(window_start), "reason": "sealed"},
            )
        return ConflictError(
            "window_sealed",
            f"window starting {iso(window_start)} ended at "
            f"{iso(window_start + s.window_ms)}, at or before the current "
            f"watermark {iso(watermark_ms)}; late reading rejected",
            detail={
                "window_start": iso(window_start),
                "watermark": iso(watermark_ms),
                "reason": "past_watermark",
            },
        )

    def _advance_probe(self, conn, probe: str, seq: int, observed_ms: int, now_ms: int) -> None:
        row = conn.execute(
            "SELECT * FROM probe_state WHERE probe = ?", (probe,)
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO probe_state (probe, contiguous_seq, frontier_time_ms,"
                " max_seq, updated_at_ms) VALUES (?,?,?,?,?)",
                (probe, 0, None, 0, now_ms),
            )
            contiguous, frontier, max_seq = 0, None, 0
        else:
            contiguous, frontier, max_seq = (
                row["contiguous_seq"],
                row["frontier_time_ms"],
                row["max_seq"],
            )

        max_seq = max(max_seq, seq)
        if seq > contiguous:
            # Extend the contiguous prefix as far as disposed readings allow.
            # An accepted reading supplies its observation time; a rejected
            # reading (tombstone) fills the sequence position but supplies no
            # time, so the frontier/watermark never move because of it.  A
            # genuinely missing seq still halts the walk: no fabricated
            # progress from out-of-order or missing sequence numbers.
            cur = contiguous
            while True:
                nxt = conn.execute(
                    "SELECT observed_at_ms, 0 AS is_rejected FROM readings"
                    " WHERE probe = ? AND seq = ?"
                    " UNION ALL"
                    " SELECT observed_at_ms, 1 AS is_rejected FROM rejected_readings"
                    " WHERE probe = ? AND seq = ?",
                    (probe, cur + 1, probe, cur + 1),
                ).fetchone()
                if nxt is None:
                    break
                cur += 1
                if not nxt["is_rejected"]:
                    frontier = nxt["observed_at_ms"] if frontier is None else max(
                        frontier, nxt["observed_at_ms"]
                    )
            contiguous = cur

        conn.execute(
            "UPDATE probe_state SET contiguous_seq = ?, frontier_time_ms = ?,"
            " max_seq = ?, updated_at_ms = ? WHERE probe = ?",
            (contiguous, frontier, max_seq, now_ms, probe),
        )

    def _watermark(self, conn) -> int | None:
        rows = conn.execute("SELECT probe, frontier_time_ms FROM probe_state").fetchall()
        frontiers = {r["probe"]: r["frontier_time_ms"] for r in rows}
        times = []
        for probe in self.settings.probes:
            t = frontiers.get(probe)
            if t is None:
                return None  # probe absent or only gapped data: no watermark
            times.append(t)
        return min(times) - self.settings.lateness_ms

    # ----------------------------------------------------------------- sealing

    def _seal_windows(self, conn, watermark_ms: int | None, now_ms: int) -> list[dict]:
        if watermark_ms is None:
            return []
        s = self.settings
        first = conn.execute("SELECT MIN(observed_at_ms) AS m FROM readings").fetchone()["m"]
        if first is None:
            return []
        start = (first // s.window_ms) * s.window_ms
        sealed = []
        w = start
        # Only windows whose end is not later than the watermark may seal.
        while w + s.window_ms <= watermark_ms:
            exists = conn.execute(
                "SELECT 1 FROM windows WHERE window_start_ms = ?", (w,)
            ).fetchone()
            if exists is None:
                sealed.append(self._seal_one(conn, w, watermark_ms, now_ms))
            w += s.window_ms
        return sealed

    def _seal_one(self, conn, window_start: int, watermark_ms: int, now_ms: int) -> dict:
        s = self.settings
        rows = conn.execute(
            "SELECT event_id, probe, seq, observed_at_ms, dose FROM readings"
            " WHERE observed_at_ms >= ? AND observed_at_ms < ?"
            " ORDER BY observed_at_ms, probe, seq",
            (window_start, window_start + s.window_ms),
        ).fetchall()
        total = sum(r["dose"] for r in rows)
        peak = max((r["dose"] for r in rows), default=0.0)
        level = self._level(total, peak)
        violation = self._first_violation(rows) if level != "NORMAL" else None
        progress = self._progress(conn)
        conn.execute(
            "INSERT INTO windows (window_start_ms, window_end_ms, total_dose, peak_dose,"
            " event_count, level, first_violation_json, watermark_ms, progress_json,"
            " sealed_at_ms) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                window_start,
                window_start + s.window_ms,
                total,
                peak,
                len(rows),
                level,
                json.dumps(violation) if violation else None,
                watermark_ms,
                json.dumps(progress, sort_keys=True),
                now_ms,
            ),
        )
        return {
            "window_start": iso(window_start),
            "window_end": iso(window_start + s.window_ms),
            "level": level,
            "total_dose": total,
            "peak_dose": peak,
            "event_count": len(rows),
        }

    def _level(self, total: float, peak: float) -> str:
        s = self.settings
        if total >= s.critical_total or peak >= s.critical_peak:
            return "CRITICAL"
        if total >= s.elevated_total or peak >= s.elevated_peak:
            return "ELEVATED"
        return "NORMAL"

    def _first_violation(self, rows) -> dict | None:
        """First event (observation order) that pushed the window out of NORMAL.

        Either its own dose breaches the elevated peak threshold, or the
        running total crosses the elevated total threshold at that event.
        """
        s = self.settings
        running = 0.0
        for r in rows:
            running += r["dose"]
            if r["dose"] >= s.elevated_peak or running >= s.elevated_total:
                return {
                    "event_id": r["event_id"],
                    "probe": r["probe"],
                    "seq": r["seq"],
                    "observed_at": iso(r["observed_at_ms"]),
                    "dose": r["dose"],
                }
        return None

    # ------------------------------------------------------------------ reads

    def _progress(self, conn) -> dict:
        rows = conn.execute("SELECT * FROM probe_state").fetchall()
        by_probe = {r["probe"]: r for r in rows}
        out = {}
        for probe in self.settings.probes:
            r = by_probe.get(probe)
            out[probe] = {
                "contiguous_seq": r["contiguous_seq"] if r else 0,
                "frontier_time": iso(r["frontier_time_ms"])
                if r and r["frontier_time_ms"] is not None
                else None,
                "max_seq": r["max_seq"] if r else 0,
            }
        return out

    def _window_events(self, conn, window_start: int) -> list[dict]:
        rows = conn.execute(
            "SELECT event_id, probe, seq, observed_at_ms, dose FROM readings"
            " WHERE observed_at_ms >= ? AND observed_at_ms < ?"
            " ORDER BY observed_at_ms, probe, seq",
            (window_start, window_start + self.settings.window_ms),
        ).fetchall()
        return [
            {
                "event_id": r["event_id"],
                "probe": r["probe"],
                "seq": r["seq"],
                "observed_at": iso(r["observed_at_ms"]),
                "dose": r["dose"],
            }
            for r in rows
        ]

    def get_window(self, when_ms: int) -> dict:
        """Read one window.  Sealed windows return the immutable published
        record; open windows return a clearly-marked provisional view."""
        s = self.settings
        w = (when_ms // s.window_ms) * s.window_ms
        with self.storage.read_txn() as conn:
            row = conn.execute(
                "SELECT * FROM windows WHERE window_start_ms = ?", (w,)
            ).fetchone()
            events = self._window_events(conn, w)
            if row is not None:
                return {
                    "window_start": iso(w),
                    "window_end": iso(w + s.window_ms),
                    "status": "sealed",
                    "final": True,
                    "level": row["level"],
                    "total_dose": row["total_dose"],
                    "peak_dose": row["peak_dose"],
                    "event_count": row["event_count"],
                    "first_violation": json.loads(row["first_violation_json"])
                    if row["first_violation_json"]
                    else None,
                    "progress_at_seal": json.loads(row["progress_json"]),
                    "watermark_at_seal": iso(row["watermark_ms"]),
                    "sealed_at": iso(row["sealed_at_ms"]),
                    "events": events,
                }
            total = sum(e["dose"] for e in events)
            peak = max((e["dose"] for e in events), default=0.0)
            watermark_ms = self._watermark(conn)
            return {
                "window_start": iso(w),
                "window_end": iso(w + s.window_ms),
                "status": "open",
                "final": False,
                # a window at or behind the watermark no longer accepts data,
                # even if it was never physically sealed (empty, pre-anchor)
                "accepting": watermark_ms is None or (w + s.window_ms) > watermark_ms,
                "level": self._level(total, peak),
                "total_dose": total,
                "peak_dose": peak,
                "event_count": len(events),
                "first_violation": None,
                "progress_at_seal": None,
                "watermark_at_seal": None,
                "sealed_at": None,
                "current_watermark": iso(watermark_ms),
                "events": events,
            }

    def list_windows(self, since_ms: int | None, until_ms: int | None) -> list[dict]:
        query = (
            "SELECT window_start_ms, window_end_ms, level, total_dose, peak_dose,"
            " event_count, sealed_at_ms FROM windows"
        )
        clauses, params = [], []
        if since_ms is not None:
            clauses.append("window_start_ms >= ?")
            params.append(since_ms)
        if until_ms is not None:
            clauses.append("window_start_ms <= ?")
            params.append(until_ms)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY window_start_ms"
        with self.storage.read_txn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "window_start": iso(r["window_start_ms"]),
                "window_end": iso(r["window_end_ms"]),
                "status": "sealed",
                "level": r["level"],
                "total_dose": r["total_dose"],
                "peak_dose": r["peak_dose"],
                "event_count": r["event_count"],
                "sealed_at": iso(r["sealed_at_ms"]),
            }
            for r in rows
        ]

    def state(self) -> dict:
        with self.storage.read_txn() as conn:
            watermark_ms = self._watermark(conn)
            progress = self._progress(conn)
            sealed = conn.execute("SELECT COUNT(*) AS c FROM windows").fetchone()["c"]
            readings = conn.execute("SELECT COUNT(*) AS c FROM readings").fetchone()["c"]
            rejected = conn.execute(
                "SELECT COUNT(*) AS c FROM rejected_readings"
            ).fetchone()["c"]
        s = self.settings
        return {
            "watermark": iso(watermark_ms),
            "probes": progress,
            "sealed_window_count": sealed,
            "reading_count": readings,
            "rejected_reading_count": rejected,
            "config": {
                "window_seconds": s.window_seconds,
                "allowed_lateness_seconds": s.allowed_lateness_seconds,
                "elevated_total": s.elevated_total,
                "elevated_peak": s.elevated_peak,
                "critical_total": s.critical_total,
                "critical_peak": s.critical_peak,
                "probes": list(s.probes),
            },
        }

    def health_check(self) -> None:
        with self.storage.read_txn() as conn:
            conn.execute("SELECT 1").fetchone()
