"""Generic multi-site username probe."""

from __future__ import annotations

import asyncio

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta
from osintx.providers.username.sites import SITES
from osintx.ratelimit import TokenBucket

class GenericUsernameProvider(BaseProvider):
    meta = ProviderMeta(
        name="username-generic",
        category="username",
        description="Probe ~80 platforms for username existence",
        targets=("username",),
        rate=8.0,
        burst=8,
        timeout=90.0,
    )

    async def _probe(self, site: dict, username: str, bucket: TokenBucket) -> Finding | None:
        await bucket.acquire()
        check = site["check"].format(u=username)
        try:
            response = await self.ctx.http.get(
                check,
                headers={"Accept": "text/html,application/json;q=0.9,*/*;q=0.8"},
                allow_status=tuple(range(200, 600)),
            )
        except Exception:
            return None

        if response.status_code == 404:
            return None
        if response.status_code >= 400 and response.status_code not in {403, 429}:
            return None

        body = response.text[:200_000]
        markers = site.get("markers") or []
        if markers and any(marker in body for marker in markers):
            return None
        if not markers and response.status_code != 200:
            return None

        return Finding(
            provider=self.name,
            category="username",
            title=f"Account found on {site['name']}",
            severity=Severity.LOW,
            url=site["url"].format(u=username),
            data={"site": site["name"], "status": response.status_code},
        )

    async def run(self, target: Target) -> list[Finding]:
        bucket = TokenBucket(self.meta.rate, burst=self.meta.burst)
        tasks = [asyncio.create_task(self._probe(site, target.value, bucket)) for site in SITES]
        findings: list[Finding] = []
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result is not None:
                findings.append(result)
        return findings
