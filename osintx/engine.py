"""Async scan orchestrator: scheduling, timeouts, dedupe, persistence."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Awaitable, Callable

from osintx.config import Config
from osintx.http import HttpClient
from osintx.models import (
    Finding,
    ProviderOutcome,
    ScanResult,
    ScanStatus,
    Target,
)
from osintx.providers.base import BaseProvider, ProviderContext
from osintx.storage import Storage

log = logging.getLogger("osintx.engine")

EventHook = Callable[[str, dict], Awaitable[None] | None]

class Engine:
    def __init__(
        self,
        config: Config,
        storage: Storage,
        providers: list[BaseProvider],
        on_event: EventHook | None = None,
    ) -> None:
        self.config = config
        self.storage = storage
        self.providers = providers
        self.on_event = on_event
        self._semaphore = asyncio.Semaphore(max(1, config.concurrency))
        self._seen: set[str] = set()

    # ------------------------------------------------------------------
    async def _emit(self, event: str, payload: dict) -> None:
        if self.on_event is None:
            return
        try:
            result = self.on_event(event, payload)
            if asyncio.iscoroutine(result):
                await result
        except Exception:  # pragma: no cover - hooks must never break a scan
            log.debug("event hook failed", exc_info=True)

    # ------------------------------------------------------------------
    async def _run_provider(
        self, provider: BaseProvider, target: Target, result: ScanResult
    ) -> ProviderOutcome:
        outcome = ProviderOutcome(provider=provider.name, category=provider.meta.category, ok=False)
        started = time.perf_counter()
        async with self._semaphore:
            await self._emit("provider_start", {"provider": provider.name, "category": provider.meta.category})
            try:
                findings = await asyncio.wait_for(
                    provider.run(target), timeout=provider.meta.timeout
                )
                outcome.ok = True
                for finding in findings:
                    marker = finding.fingerprint()
                    if marker in self._seen:
                        continue
                    self._seen.add(marker)
                    result.add(finding)
                    outcome.findings.append(finding)
                    await self._emit(
                        "finding",
                        {
                            "provider": finding.provider,
                            "category": finding.category,
                            "title": finding.title,
                            "severity": finding.severity.value,
                            "url": finding.url,
                            "data": finding.data,
                        },
                    )
            except asyncio.TimeoutError:
                outcome.error = f"timeout after {provider.meta.timeout}s"
            except Exception as exc:  # noqa: BLE001
                outcome.error = f"{type(exc).__name__}: {exc}"
                log.debug("provider %s failed", provider.name, exc_info=True)
        outcome.elapsed = time.perf_counter() - started
        await self._emit(
            "provider_done",
            {
                "provider": provider.name,
                "ok": outcome.ok,
                "error": outcome.error,
                "elapsed": round(outcome.elapsed, 3),
                "count": len(outcome.findings),
            },
        )
        return outcome

    # ------------------------------------------------------------------
    async def run(self, target: Target, providers: list[BaseProvider] | None = None) -> ScanResult:
        selected = providers if providers is not None else self.providers
        result = ScanResult(target=target.value, target_type=target.type, status=ScanStatus.RUNNING)
        await self.storage.create_scan(result)
        await self._emit("scan_start", {"id": result.id, "target": target.value, "type": target.type.value})

        async with HttpClient(self.config) as http:
            ctx = ProviderContext(config=self.config, http=http, storage=self.storage)
            runnable: list[BaseProvider] = []
            for provider in selected:
                provider.ctx = ctx
                if not provider.available():
                    result.outcomes.append(
                        ProviderOutcome(
                            provider=provider.name,
                            category=provider.meta.category,
                            ok=False,
                            skipped=True,
                            error="missing credentials",
                        )
                    )
                    await self._emit(
                        "provider_skipped",
                        {"provider": provider.name, "reason": "missing credentials"},
                    )
                    continue
                runnable.append(provider)

            tasks = [asyncio.create_task(self._run_provider(p, target, result)) for p in runnable]
            if tasks:
                for coro in asyncio.as_completed(tasks):
                    result.outcomes.append(await coro)

        result.status = ScanStatus.DONE
        result.finished_at = result.created_at
        await self.storage.save_findings(result.id, result.findings)
        await self.storage.update_status(result.id, result.status, result.stats())
        await self._emit("scan_done", {"id": result.id, "stats": result.stats()})
        return result
