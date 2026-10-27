"""Disk cache for HTTP responses (TTL-based)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from osintx.utils import sha256

class DiskCache:
    def __init__(self, directory: Path, ttl: int) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl

    def _path(self, key: str) -> Path:
        return self.directory / f"{sha256(key)}.json"

    def get(self, key: str) -> Any | None:
        path = self._path(key)
        if not path.is_file():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if time.time() - payload.get("ts", 0) > self.ttl:
            return None
        return payload.get("value")

    def set(self, key: str, value: Any) -> None:
        payload = {"ts": time.time(), "value": value}
        try:
            self._path(key).write_text(json.dumps(payload, default=str), encoding="utf-8")
        except OSError:
            pass

    def clear(self) -> int:
        removed = 0
        for path in self.directory.glob("*.json"):
            try:
                path.unlink()
                removed += 1
            except OSError:
                pass
        return removed
