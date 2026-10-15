"""Local submission history (SQLite), used to skip re-submitting known files.

Stored per finished analysis: the file's SHA-256 and base name (never the full path or the
file itself), the appliance host, submission ID, time, verdict and the raw results response
so a cached result can be re-parsed with full detail (alerts, IOCs).

Location, in order of precedence: ``--history PATH``, ``$IVX_HISTORY``, then
``%LOCALAPPDATA%\\ivx-toolkit\\history.db`` on Windows or
``$XDG_DATA_HOME/ivx-toolkit/history.db`` (default ``~/.local/share``) elsewhere.

The raw responses can contain environment details; the database stays on this machine
and is only readable by the current user on POSIX systems.
"""

from __future__ import annotations

import os
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

FINAL_VERDICTS = ("malicious", "suspicious", "no-detection")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS submissions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256        TEXT NOT NULL,
    file_name     TEXT NOT NULL,
    host          TEXT NOT NULL,
    submission_id TEXT NOT NULL,
    submitted_at  TEXT NOT NULL,
    verdict       TEXT NOT NULL,
    malware       TEXT NOT NULL DEFAULT '',
    content_type  TEXT NOT NULL DEFAULT '',
    raw           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_submissions_sha_host ON submissions (sha256, host);
"""


def default_path() -> Path:
    env = os.environ.get("IVX_HISTORY")
    if env:
        return Path(env)
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "ivx-toolkit" / "history.db"


@dataclass
class Entry:
    sha256: str
    file_name: str
    host: str
    submission_id: str
    submitted_at: str
    verdict: str
    malware: str
    content_type: str = ""
    raw: str = ""


def _now() -> datetime:
    return datetime.now(timezone.utc)


class History:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else default_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        new = not self.path.exists()
        self.db = sqlite3.connect(str(self.path))
        self.db.executescript(_SCHEMA)
        if new and os.name == "posix":
            os.chmod(self.path, 0o600)

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> History:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def record(
        self,
        sha256: str,
        file_name: str,
        host: str,
        submission_id: str,
        verdict: str,
        malware: str = "",
        content_type: str = "",
        raw: str = "",
        when: datetime | None = None,
    ) -> None:
        if verdict not in FINAL_VERDICTS:
            return  # never cache errors or unfinished analyses
        self.db.execute(
            "INSERT INTO submissions (sha256, file_name, host, submission_id, submitted_at,"
            " verdict, malware, content_type, raw) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                sha256.lower(),
                Path(file_name).name,
                host.lower(),
                submission_id,
                (when or _now()).isoformat(timespec="seconds"),
                verdict,
                malware,
                content_type,
                raw,
            ),
        )
        self.db.commit()

    def lookup(self, sha256: str, host: str, max_age_days: float) -> Entry | None:
        """Most recent final result for this file on this appliance, if fresh enough."""
        cutoff = (_now() - timedelta(days=max_age_days)).isoformat(timespec="seconds")
        row = self.db.execute(
            "SELECT sha256, file_name, host, submission_id, submitted_at, verdict, malware,"
            " content_type, raw FROM submissions WHERE sha256 = ? AND host = ?"
            " AND submitted_at >= ? ORDER BY submitted_at DESC, id DESC LIMIT 1",
            (sha256.lower(), host.lower(), cutoff),
        ).fetchone()
        return Entry(*row) if row else None

    def recent(self, limit: int = 50, sha256: str | None = None) -> list[Entry]:
        query = (
            "SELECT sha256, file_name, host, submission_id, submitted_at, verdict, malware"
            " FROM submissions"
        )
        params: tuple = ()
        if sha256:
            query += " WHERE sha256 = ?"
            params = (sha256.lower(),)
        query += " ORDER BY submitted_at DESC, id DESC LIMIT ?"
        rows = self.db.execute(query, (*params, limit)).fetchall()
        return [Entry(*row) for row in rows]
