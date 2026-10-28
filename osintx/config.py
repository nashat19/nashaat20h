from __future__ import annotations
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

def _load_env(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

_load_env(Path(".env"))
_load_env(Path.home() / ".osintx.env")

@dataclass
class Config:
    timeout: float = float(os.environ.get("OSINTX_TIMEOUT", "20"))
    concurrency: int = int(os.environ.get("OSINTX_CONCURRENCY", "8"))
    rate: float = float(os.environ.get("OSINTX_RATE", "3"))
    burst: int = int(os.environ.get("OSINTX_BURST", "6"))
    retries: int = int(os.environ.get("OSINTX_RETRIES", "2"))
    user_agent: str = os.environ.get("OSINTX_UA", "OSINTX/2.0 (+https://github.com/osintx)")
    region: str = os.environ.get("OSINTX_REGION", "IQ")
    keys: Dict[str, str] = field(default_factory=lambda: {
        "hibp": os.environ.get("HIBP_KEY", ""),
        "leakcheck": os.environ.get("LEAKCHECK_KEY", ""),
        "dehashed": os.environ.get("DEHASHED_KEY", ""),
        "intelx": os.environ.get("INTELX_KEY", ""),
        "snusbase": os.environ.get("SNUSBASE_KEY", ""),
        "shodan": os.environ.get("SHODAN_KEY", ""),
    })
    def key(self, name: str) -> str:
        return self.keys.get(name, "")
