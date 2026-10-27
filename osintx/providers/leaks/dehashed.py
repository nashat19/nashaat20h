"""DeHashed — leaked credential & PII search."""

from __future__ import annotations

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

API = "https://api.dehashed.com/search"

class DehashedProvider(BaseProvider):
    meta = ProviderMeta(
        name="dehashed",
        category="leaks",
        description="DeHashed leaked credential search",
        targets=("email", "username", "phone", "domain", "ip"),
        requires_key=True,
        key_attr="dehashed_key",
        rate=0.5,
        burst=1,
        timeout=35.0,
    )

    def available(self) -> bool:
        cfg = self.ctx.config
        return bool(cfg.dehashed_key and cfg.dehashed_email)

    async def run(self, target: Target) -> list[Finding]:
        field = {
            "email": "email",
            "username": "username",
            "phone": "phone",
            "domain": "domain",
            "ip": "ip_address",
        }.get(target.type.value, "email")

        response = await self.ctx.http.get(
            API,
            params={"query": f'{field}:"{target.value}"', "size": 100},
            auth=(self.ctx.config.dehashed_email, self.ctx.config.dehashed_key),
            headers={"Accept": "application/json"},
            allow_status=(200, 400, 401, 403, 429),
        )
        if response.status_code in {401, 403}:
            raise RuntimeError("invalid DeHashed credentials")
        payload = response.json() or {}
        entries = payload.get("entries") or []

        findings: list[Finding] = []
        for entry in entries:
            has_password = bool(entry.get("password"))
            findings.append(
                Finding(
                    provider=self.name,
                    category="leaks",
                    title=f"DeHashed record — {entry.get('database_name') or 'unknown'}",
                    severity=Severity.CRITICAL if has_password else Severity.HIGH,
                    data={
                        "database": entry.get("database_name"),
                        "email": entry.get("email"),
                        "username": entry.get("username"),
                        "password": entry.get("password"),
                        "hashed_password": entry.get("hashed_password"),
                        "phone": entry.get("phone"),
                        "name": entry.get("name"),
                        "address": entry.get("address"),
                        "ip_address": entry.get("ip_address"),
                    },
                )
            )
        return findings
