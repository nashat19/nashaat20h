"""Intelligence X — phonebook search (async job + poll)."""

from __future__ import annotations

import asyncio

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

BASE = "https://2.intelx.io"

class IntelXProvider(BaseProvider):
    meta = ProviderMeta(
        name="intelx",
        category="leaks",
        description="Intelligence X phonebook / leak index",
        targets=("email", "username", "phone", "domain"),
        requires_key=True,
        key_attr="intelx_key",
        rate=0.5,
        burst=1,
        timeout=60.0,
    )

    async def run(self, target: Target) -> list[Finding]:
        headers = {"x-key": self.ctx.config.intelx_key, "Content-Type": "application/json"}
        body = {
            "term": target.value,
            "maxresults": 100,
            "media": 0,
            "target": 0,
            "terminate": [],
        }
        start = await self.ctx.http.post(
            f"{BASE}/phonebook/search",
            headers=headers,
            json=body,
            allow_status=(200, 400, 401, 403, 429),
        )
        if start.status_code in {401, 403}:
            raise RuntimeError("invalid Intelligence X key")
        search_id = (start.json() or {}).get("id")
        if not search_id:
            return []

        records: list[dict] = []
        for _ in range(12):
            await asyncio.sleep(2.0)
            poll = await self.ctx.http.get(
                f"{BASE}/phonebook/search/result",
                headers=headers,
                params={"id": search_id, "limit": 100},
                allow_status=(200, 202, 404, 429),
            )
            if poll.status_code == 404:
                break
            payload = poll.json() or {}
            records = payload.get("records") or []
            status = payload.get("status")
            if status in {1, 2} and records:
                break

        findings: list[Finding] = []
        for record in records:
            bucket = record.get("bucket") or "leak"
            findings.append(
                Finding(
                    provider=self.name,
                    category="leaks",
                    title=f"IntelX {bucket} record",
                    severity=Severity.HIGH,
                    data={
                        "bucket": bucket,
                        "name": record.get("name"),
                        "date": record.get("date"),
                        "storage_id": record.get("storageid"),
                        "media_type": record.get("media"),
                    },
                )
            )
        return findings
