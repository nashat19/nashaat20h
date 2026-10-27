"""Leak-Lookup — multi-database breach search."""

from __future__ import annotations

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

API = "https://leak-lookup.com/api/search"

class LeakLookupProvider(BaseProvider):
    meta = ProviderMeta(
        name="leaklookup",
        category="leaks",
        description="Leak-Lookup aggregated breach search",
        targets=("email", "username", "phone", "domain"),
        requires_key=True,
        key_attr="leaklookup_key",
        rate=0.5,
        burst=1,
        timeout=30.0,
    )

    async def run(self, target: Target) -> list[Finding]:
        response = await self.ctx.http.post(
            API,
            data={
                "key": self.ctx.config.leaklookup_key,
                "type": target.type.value,
                "query": target.value,
            },
            allow_status=(200, 400, 401, 403, 429),
        )
        if response.status_code in {401, 403}:
            raise RuntimeError("invalid Leak-Lookup key")
        payload = response.json() or {}
        if payload.get("error") == "true":
            return []
        message = payload.get("message") or {}

        findings: list[Finding] = []
        for database, rows in message.items():
            for row in rows or []:
                findings.append(
                    Finding(
                        provider=self.name,
                        category="leaks",
                        title=f"Leak-Lookup record — {database}",
                        severity=Severity.HIGH,
                        data={"database": database, **row},
                    )
                )
        return findings
