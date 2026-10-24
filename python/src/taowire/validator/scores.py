"""Validator score persistence: SQLite with a per-UID EMA (spec 8.9, ADR-0005).

One file, ``TW_STATE_DIR/scores.db``, in WAL mode, written by one process.
Scores survive restarts. Each round moves a miner's score towards the
round's value::

    s = alpha * new + (1 - alpha) * s

A UID whose hotkey changed (deregistered and re-registered by someone else)
starts again from zero: the new owner never inherits the old one's score.
UIDs that left the metagraph are dropped.

Every method is synchronous and quick; async callers run them in a worker
thread (``anyio.to_thread.run_sync``).
"""

from __future__ import annotations

import math
import sqlite3
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

__all__ = ["RoundRecord", "ScoreStore", "WeightRecord"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scores (
  netuid INTEGER NOT NULL, uid INTEGER NOT NULL, hotkey TEXT NOT NULL,
  score REAL NOT NULL, updated_block INTEGER NOT NULL,
  PRIMARY KEY (netuid, uid));
CREATE TABLE IF NOT EXISTS rounds (
  id INTEGER PRIMARY KEY, netuid INTEGER, started_at REAL, n_queried INTEGER,
  n_ok INTEGER, p50_ms REAL, p95_ms REAL);
CREATE TABLE IF NOT EXISTS weight_submissions (
  id INTEGER PRIMARY KEY, netuid INTEGER, block INTEGER, ok INTEGER,
  code TEXT, n_uids INTEGER, block_hash TEXT);
"""


@dataclass(frozen=True)
class RoundRecord:
    """One validator round, as stored in ``rounds``."""

    started_at: float
    n_queried: int
    n_ok: int
    p50_ms: float | None
    p95_ms: float | None


@dataclass(frozen=True)
class WeightRecord:
    """One ``set_weights`` submission, as stored in ``weight_submissions``."""

    block: int
    ok: bool
    code: str | None
    n_uids: int
    block_hash: str | None


class ScoreStore:
    """Per-UID EMA scores for one subnet, in SQLite.

    ``path`` may be ``":memory:"`` (tests). The parent directory is created
    with mode 0700.
    """

    def __init__(self, path: Path | str, netuid: int, *, alpha: float) -> None:
        if not 0 < alpha <= 1:
            raise ValueError("alpha must be in (0, 1]")
        if str(path) != ":memory:":
            Path(path).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.netuid = netuid
        self.alpha = float(alpha)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript(_SCHEMA)
        self._db.commit()

    def close(self) -> None:
        """Close the database. Safe to call more than once."""
        with self._lock:
            self._db.close()

    # ------------------------------------------------------------ scores

    def sync_hotkeys(self, hotkeys: Mapping[int, str]) -> dict[int, str]:
        """Align stored UIDs with the metagraph's ``uid -> hotkey`` map.

        Drops UIDs no longer in the map and resets UIDs whose hotkey changed.
        Returns ``{uid: old_hotkey}`` for every dropped or reset UID.
        """
        with self._lock:
            rows = self._db.execute(
                "SELECT uid, hotkey FROM scores WHERE netuid = ?", (self.netuid,)
            ).fetchall()
            gone = {uid: hk for uid, hk in rows if hotkeys.get(uid) != hk}
            self._db.executemany(
                "DELETE FROM scores WHERE netuid = ? AND uid = ?",
                [(self.netuid, uid) for uid in gone],
            )
            self._db.commit()
        return gone

    def update(
        self, new_scores: Mapping[int, float], hotkeys: Mapping[int, str], block: int
    ) -> None:
        """Fold one round's scores (each in [0, 1]) into the EMA.

        ``hotkeys`` maps every scored UID to its current hotkey; a UID with a
        different stored hotkey starts from zero. Values are clamped to
        [0, 1]; NaN counts as 0.
        """
        missing = [uid for uid in new_scores if uid not in hotkeys]
        if missing:
            raise ValueError(f"no hotkey for scored uid(s) {sorted(missing)}")
        with self._lock:
            current = {
                uid: (hk, score)
                for uid, hk, score in self._db.execute(
                    "SELECT uid, hotkey, score FROM scores WHERE netuid = ?",
                    (self.netuid,),
                )
            }
            rows = []
            for uid, value in new_scores.items():
                hotkey = hotkeys[uid]
                old_hotkey, old = current.get(uid, (hotkey, 0.0))
                if old_hotkey != hotkey:
                    old = 0.0
                ema = self.alpha * _clamp(value) + (1 - self.alpha) * old
                rows.append((self.netuid, uid, hotkey, ema, block))
            self._db.executemany(
                "INSERT INTO scores (netuid, uid, hotkey, score, updated_block) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT (netuid, uid) DO UPDATE SET "
                "hotkey = excluded.hotkey, score = excluded.score, "
                "updated_block = excluded.updated_block",
                rows,
            )
            self._db.commit()

    def scores(self) -> dict[int, float]:
        """Current EMA score per UID."""
        with self._lock:
            return dict(
                self._db.execute(
                    "SELECT uid, score FROM scores WHERE netuid = ? ORDER BY uid",
                    (self.netuid,),
                ).fetchall()
            )

    def hotkeys(self) -> dict[int, str]:
        """Stored hotkey per UID."""
        with self._lock:
            return dict(
                self._db.execute(
                    "SELECT uid, hotkey FROM scores WHERE netuid = ?", (self.netuid,)
                ).fetchall()
            )

    # ------------------------------------------------------------ history

    def record_round(self, record: RoundRecord) -> int:
        """Store one round; returns its id."""
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO rounds (netuid, started_at, n_queried, n_ok, p50_ms, "
                "p95_ms) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    self.netuid,
                    record.started_at,
                    record.n_queried,
                    record.n_ok,
                    record.p50_ms,
                    record.p95_ms,
                ),
            )
            self._db.commit()
            return int(cur.lastrowid or 0)

    def record_weights(self, record: WeightRecord) -> None:
        """Store one weight submission."""
        with self._lock:
            self._db.execute(
                "INSERT INTO weight_submissions (netuid, block, ok, code, n_uids, "
                "block_hash) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    self.netuid,
                    record.block,
                    int(record.ok),
                    record.code,
                    record.n_uids,
                    record.block_hash,
                ),
            )
            self._db.commit()

    def last_rounds(self, n: int = 10) -> list[RoundRecord]:
        """The ``n`` most recent rounds, newest first."""
        with self._lock:
            rows = self._db.execute(
                "SELECT started_at, n_queried, n_ok, p50_ms, p95_ms FROM rounds "
                "WHERE netuid = ? ORDER BY id DESC LIMIT ?",
                (self.netuid, n),
            ).fetchall()
        return [RoundRecord(*row) for row in rows]

    def last_weights(self, n: int = 10) -> list[WeightRecord]:
        """The ``n`` most recent weight submissions, newest first."""
        with self._lock:
            rows = self._db.execute(
                "SELECT block, ok, code, n_uids, block_hash FROM weight_submissions "
                "WHERE netuid = ? ORDER BY id DESC LIMIT ?",
                (self.netuid, n),
            ).fetchall()
        return [WeightRecord(b, bool(ok), c, n_uids, h) for b, ok, c, n_uids, h in rows]

    def next_round_id(self) -> int:
        """1 + the number of rounds stored for this subnet."""
        with self._lock:
            (count,) = self._db.execute(
                "SELECT COUNT(*) FROM rounds WHERE netuid = ?", (self.netuid,)
            ).fetchone()
        return int(count) + 1


def _clamp(value: float) -> float:
    if not math.isfinite(value):
        return 0.0 if math.isnan(value) else (1.0 if value > 0 else 0.0)
    return min(1.0, max(0.0, float(value)))
