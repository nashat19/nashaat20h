"""SQLite persistence for scans and findings."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from typing import Any

from osintx.models import Finding, ScanResult, ScanStatus, Severity, TargetType, utcnow

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    finished_at TEXT,
    stats TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    url TEXT,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
"""

class Storage:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    # ------------------------------------------------------------------
    async def create_scan(self, result: ScanResult) -> None:
        def work() -> None:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO scans (id, target, target_type, status, created_at) "
                    "VALUES (?,?,?,?,?)",
                    (
                        result.id,
                        result.target,
                        result.target_type.value,
                        result.status.value,
                        result.created_at,
                    ),
                )

        await asyncio.to_thread(work)

    async def update_status(self, scan_id: str, status: ScanStatus, stats: dict | None = None) -> None:
        def work() -> None:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE scans SET status=?, finished_at=?, stats=? WHERE id=?",
                    (
                        status.value,
                        utcnow() if status in {ScanStatus.DONE, ScanStatus.FAILED, ScanStatus.CANCELLED} else None,
                        json.dumps(stats or {}, default=str),
                        scan_id,
                    ),
                )

        await asyncio.to_thread(work)

    async def save_findings(self, scan_id: str, findings: list[Finding]) -> None:
        if not findings:
            return

        def work() -> None:
            with self._connect() as conn:
                conn.executemany(
                    "INSERT INTO findings (scan_id, provider, category, title, severity, url, data, created_at) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    [
                        (
                            scan_id,
                            f.provider,
                            f.category,
                            f.title,
                            f.severity.value,
                            f.url,
                            json.dumps(f.data, default=str),
                            utcnow(),
                        )
                        for f in findings
                    ],
                )

        await asyncio.to_thread(work)

    # ------------------------------------------------------------------
    async def get_scan(self, scan_id: str) -> ScanResult | None:
        def work() -> ScanResult | None:
            with self._connect() as conn:
                row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
                if row is None:
                    return None
                result = ScanResult(
                    id=row["id"],
                    target=row["target"],
                    target_type=TargetType(row["target_type"]),
                    status=ScanStatus(row["status"]),
                    created_at=row["created_at"],
                    finished_at=row["finished_at"],
                )
                for frow in conn.execute(
                    "SELECT * FROM findings WHERE scan_id=? ORDER BY id", (scan_id,)
                ):
                    result.add(
                        Finding(
                            provider=frow["provider"],
                            category=frow["category"],
                            title=frow["title"],
                            severity=Severity(frow["severity"]),
                            url=frow["url"],
                            data=json.loads(frow["data"]),
                        )
                    )
                return result

        return await asyncio.to_thread(work)

    async def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        def work() -> list[dict[str, Any]]:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT id, target, target_type, status, created_at, stats "
                    "FROM scans ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
                return [dict(row) for row in rows]

        return await asyncio.to_thread(work)

    async def delete_scan(self, scan_id: str) -> None:
        def work() -> None:
            with self._connect() as conn:
                conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))

        await asyncio.to_thread(work)
