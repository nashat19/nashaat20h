"""Provider contract and shared context."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from osintx.config import Config
from osintx.http import HttpClient
from osintx.models import Finding, Target
from osintx.storage import Storage

@dataclass(frozen=True)
class ProviderMeta:
    name: str
    category: str
    description: str
    targets: tuple[str, ...]
    requires_key: bool = False
    key_attr: str | None = None
    rate: float = 1.0
    burst: int = 1
    timeout: float = 20.0
    enabled_by_default: bool = True

@dataclass
class ProviderContext:
    config: Config
    http: HttpClient
    storage: Storage

class BaseProvider(ABC):
    meta: ProviderMeta
    ctx: ProviderContext

    def __init__(self, ctx: ProviderContext | None = None) -> None:
        if ctx is not None:
            self.ctx = ctx

    @property
    def name(self) -> str:
        return self.meta.name

    def available(self) -> bool:
        if not self.meta.requires_key:
            return True
        if not self.meta.key_attr:
            return True
        return bool(getattr(self.ctx.config, self.meta.key_attr, ""))

    def supports(self, target_type: str) -> bool:
        return target_type in self.meta.targets

    @abstractmethod
    async def run(self, target: Target) -> list[Finding]:
        """Return findings for `target`. Must not raise for expected failures."""
