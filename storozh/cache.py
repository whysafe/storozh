"""SQLite cache of previous verdicts so that repeated scans skip unchanged files."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .engine import FileResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS verdicts (
    path      TEXT PRIMARY KEY,
    size      INTEGER NOT NULL,
    mtime_ns  INTEGER NOT NULL,
    profile   TEXT NOT NULL,
    result    TEXT NOT NULL
)
"""


class ScanCache:
    """A file is reused only if its size, mtime and the scan profile all match.

    The profile combines the signature database fingerprint with the scan
    options, so updating signatures or toggling heuristics forces a rescan.
    """

    def __init__(self, path: str | Path, profile: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.profile = profile
        self.conn = sqlite3.connect(self.path)
        self.conn.execute(SCHEMA)
        self.hits = 0

    def get(self, path: Path, size: int, mtime_ns: int) -> FileResult | None:
        row = self.conn.execute(
            "SELECT result FROM verdicts WHERE path = ? AND size = ? AND mtime_ns = ? AND profile = ?",
            (str(path.resolve()), size, mtime_ns, self.profile),
        ).fetchone()
        if row is None:
            return None
        self.hits += 1
        result = FileResult.from_dict(json.loads(row[0]))
        result.path = str(path)
        return result

    def put(self, path: Path, size: int, mtime_ns: int, result: FileResult) -> None:
        if result.status == "error":
            return
        self.conn.execute(
            "INSERT OR REPLACE INTO verdicts (path, size, mtime_ns, profile, result) VALUES (?, ?, ?, ?, ?)",
            (str(path.resolve()), size, mtime_ns, self.profile, json.dumps(result.to_dict(), ensure_ascii=False)),
        )

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

    def __enter__(self) -> "ScanCache":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
