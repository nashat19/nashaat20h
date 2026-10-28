from __future__ import annotations
from typing import Any, AsyncIterator, Dict, List

class Provider:
    name = "base"
    kinds: tuple = ()
    requires_key = False
    weight = 0.5

    def supports(self, kind: str) -> bool:
        return kind in self.kinds or "auto" in self.kinds

    def ready(self, cfg) -> bool:
        return not self.requires_key or bool(cfg.key(self.name))

    async def run(self, target: str, ctx: Any) -> AsyncIterator[Dict[str, Any]]:
        raise NotImplementedError
        yield {}
