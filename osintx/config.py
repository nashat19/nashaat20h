"""Runtime configuration: env vars, .env file, CLI overrides."""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

UA_POOL = (
    DEFAULT_UA,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
)

def load_dotenv(path: Path) -> None:
    """Minimal .env loader (no external dependency)."""
    if not path.is_file():
        return
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value

def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()

def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name) or default)
    except ValueError:
        return default

def _env_float(name: str, default: float) -> float:
    try:
        return float(_env(name) or default)
    except ValueError:
        return default

def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name).lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on", "y"}

@dataclass
class Config:
    """All tunables in one place."""

    # --- API credentials -------------------------------------------------
    hibp_key: str = ""
    leakcheck_key: str = ""
    dehashed_email: str = ""
    dehashed_key: str = ""
    intelx_key: str = ""
    snusbase_key: str = ""
    breachdirectory_key: str = ""
    leaklookup_key: str = ""
    emailrep_key: str = ""
    github_token: str = ""

    # --- Networking ------------------------------------------------------
    proxy: str = ""
    timeout: float = 20.0
    connect_timeout: float = 10.0
    retries: int = 3
    backoff_base: float = 0.6
    concurrency: int = 12
    global_rate: float = 25.0
    verify_tls: bool = True
    user_agents: tuple[str, ...] = UA_POOL

    # --- Behaviour -------------------------------------------------------
    cache_ttl: int = 900
    max_body_bytes: int = 2_000_000
    follow_redirects: bool = True
    verbose: bool = False
    offline: bool = False

    # --- Paths -----------------------------------------------------------
    data_dir: Path = field(default_factory=lambda: Path.home() / ".osintx")
    db_name: str = "osintx.db"

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir).expanduser()
        self.data_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    @property
    def db_path(self) -> Path:
        return self.data_dir / self.db_name

    @property
    def cache_dir(self) -> Path:
        path = self.data_dir / "cache"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def export_dir(self) -> Path:
        path = self.data_dir / "exports"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def has_key(self, env_name: str) -> bool:
        return bool(getattr(self, env_name, ""))

    # ------------------------------------------------------------------
    @classmethod
    def from_env(cls, env_file: Path | None = None) -> "Config":
        load_dotenv(env_file or Path(".env"))
        return cls(
            hibp_key=_env("OSINTX_HIBP_KEY"),
            leakcheck_key=_env("OSINTX_LEAKCHECK_KEY"),
            dehashed_email=_env("OSINTX_DEHASHED_EMAIL"),
            dehashed_key=_env("OSINTX_DEHASHED_KEY"),
            intelx_key=_env("OSINTX_INTELX_KEY"),
            snusbase_key=_env("OSINTX_SNUSBASE_KEY"),
            breachdirectory_key=_env("OSINTX_BREACHDIRECTORY_KEY"),
            leaklookup_key=_env("OSINTX_LEAKLOOKUP_KEY"),
            emailrep_key=_env("OSINTX_EMAILREP_KEY"),
            github_token=_env("OSINTX_GITHUB_TOKEN"),
            proxy=_env("OSINTX_PROXY"),
            timeout=_env_float("OSINTX_TIMEOUT", 20.0),
            retries=_env_int("OSINTX_RETRIES", 3),
            concurrency=_env_int("OSINTX_CONCURRENCY", 12),
            global_rate=_env_float("OSINTX_RATE", 25.0),
            cache_ttl=_env_int("OSINTX_CACHE_TTL", 900),
            verify_tls=not _env_bool("OSINTX_INSECURE"),
            verbose=_env_bool("OSINTX_VERBOSE"),
            offline=_env_bool("OSINTX_OFFLINE"),
            data_dir=Path(_env("OSINTX_DATA_DIR") or (Path.home() / ".osintx")),
        )

    # ------------------------------------------------------------------
    def redacted(self) -> dict[str, Any]:
        """Serialisable view with secrets masked."""
        out: dict[str, Any] = {}
        for key, value in asdict(self).items():
            if isinstance(value, Path):
                out[key] = str(value)
            elif isinstance(value, tuple):
                out[key] = list(value)
            elif key.endswith(("_key", "_token")) and value:
                out[key] = f"{str(value)[:4]}…{str(value)[-4:]}"
            else:
                out[key] = value
        return out
