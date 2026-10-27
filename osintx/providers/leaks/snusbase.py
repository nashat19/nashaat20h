"""Snusbase — leaked database search."""

from __future__ import annotations

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

API = "https://api.snusbase.com/data/search"

TYPE_MAP = {
    "email": "email",
    "username": "username",
    "phone": "phone",
    "domain": "domain",
    "ip": "lastip",
}

class SnusbaseProvider(BaseProvider):
    meta = ProviderMeta(
        name="snusbase",
        category="leaks",
        description="Snusbase leaked database search",
        targets=("email", "username", "phone", "domain", "ip"),
        requires_key=True,
        key_attr="snusbase_key",
        rate=0.5,
        burst=1,
        timeout=35.0,
    )

    async def run(self, target: Target) -> list[Finding]:
        response = await self.ctx.http.post(
            API,
            headers={"Auth": self.ctx.config.snusbase_key, "Content-Type": "application/json"},
            json={
                "terms": [target.value],
                "types": [TYPE_MAP.get(target.type.value, "email")],
                "wildcard": False,
            },
            allow_status=(200, 400, 401, 403, 429),
        )
        if response.status_code in {401, 403}:
            raise RuntimeError("invalid Snusbase key")
        payload = response.json() or {}
        results = payload.get("results") or {}

        findings: list[Finding] = []
        for database, rows in results.items():
            for row in rows or []:
                findings.append(
                    Finding(
                        provider=self.name,
                        category="leaks",
                        title=f"Snusbase record — {database}",
                        severity=Severity.CRITICAL if row.get("password") else Severity.HIGH,
                        data={"database": database, **row},
                    )
                )
        return findings
