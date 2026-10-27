"""LeakCheck v2 — leaked credential search."""

from __future__ import annotations

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

API = "https://leakcheck.io/api/v2/query"

class LeakCheckProvider(BaseProvider):
    meta = ProviderMeta(
        name="leakcheck",
        category="leaks",
        description="LeakCheck leaked-credential database",
        targets=("email", "username", "phone", "domain"),
        requires_key=True,
        key_attr="leakcheck_key",
        rate=1.0,
        burst=1,
        timeout=30.0,
    )

    async def run(self, target: Target) -> list[Finding]:
        response = await self.ctx.http.get(
            f"{API}/{target.value}",
            headers={"X-API-Key": self.ctx.config.leakcheck_key},
            params={"type": target.type.value, "limit": 500},
            allow_status=(200, 400, 401, 403, 404, 429),
        )
        if response.status_code in {401, 403}:
            raise RuntimeError("invalid LeakCheck key")
        if response.status_code == 404:
            return []
        payload = response.json() or {}
        if not payload.get("success"):
            return []

        findings: list[Finding] = []
        for entry in payload.get("result") or []:
            fields = entry.get("fields") or {}
            has_password = bool(entry.get("password"))
            findings.append(
                Finding(
                    provider=self.name,
                    category="leaks",
                    title=f"Leak record — {entry.get('source', {}).get('name', 'unknown source')}",
                    severity=Severity.CRITICAL if has_password else Severity.HIGH,
                    data={
                        "source": (entry.get("source") or {}).get("name"),
                        "breach_date": (entry.get("source") or {}).get("breach_date"),
                        "email": entry.get("email"),
                        "username": entry.get("username"),
                        "password": entry.get("password"),
                        "phone": entry.get("phone"),
                        "name": entry.get("name"),
                        "fields": fields,
                    },
                )
            )
        return findings
