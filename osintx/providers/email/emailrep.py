"""EmailRep.io reputation lookup."""

from __future__ import annotations

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

class EmailRepProvider(BaseProvider):
    meta = ProviderMeta(
        name="emailrep",
        category="email",
        description="EmailRep reputation & social footprint",
        targets=("email",),
        rate=1.0,
        burst=1,
        timeout=20.0,
    )

    async def run(self, target: Target) -> list[Finding]:
        headers = {"Accept": "application/json"}
        if self.ctx.config.emailrep_key:
            headers["Key"] = self.ctx.config.emailrep_key
        response = await self.ctx.http.get(
            f"https://emailrep.io/{target.value}",
            headers=headers,
            allow_status=(200, 400, 401, 429),
        )
        if response.status_code != 200:
            return []
        payload = response.json() or {}
        details = payload.get("details") or {}
        severity = Severity.MEDIUM if payload.get("suspicious") else Severity.INFO
        return [
            Finding(
                provider=self.name,
                category="email",
                title=f"EmailRep: {payload.get('reputation', 'unknown')} reputation",
                severity=severity,
                data={
                    "reputation": payload.get("reputation"),
                    "suspicious": payload.get("suspicious"),
                    "references": payload.get("references"),
                    "profiles": payload.get("profiles"),
                    "domain_exists": details.get("domain_exists"),
                    "deliverable": details.get("deliverable"),
                    "disposable": details.get("disposable"),
                    "free_provider": details.get("free_provider"),
                    "spoofable": details.get("spoofable"),
                    "days_since_domain_creation": details.get("days_since_domain_creation"),
                },
            )
        ]
