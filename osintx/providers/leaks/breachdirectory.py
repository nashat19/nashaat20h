"""BreachDirectory (RapidAPI) — breach lookup."""

from __future__ import annotations

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

API = "https://breachdirectory.p.rapidapi.com/"

class BreachDirectoryProvider(BaseProvider):
    meta = ProviderMeta(
        name="breachdirectory",
        category="leaks",
        description="BreachDirectory breach lookup",
        targets=("email", "username", "phone", "domain"),
        requires_key=True,
        key_attr="breachdirectory_key",
        rate=1.0,
        burst=1,
        timeout=25.0,
    )

    async def run(self, target: Target) -> list[Finding]:
        response = await self.ctx.http.get(
            API,
            params={"func": "auto", "term": target.value},
            headers={
                "X-RapidAPI-Key": self.ctx.config.breachdirectory_key,
                "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
            },
            allow_status=(200, 400, 401, 403, 429),
        )
        if response.status_code in {401, 403}:
            raise RuntimeError("invalid BreachDirectory key")
        payload = response.json() or {}
        if not payload.get("success"):
            return []

        findings: list[Finding] = []
        for entry in payload.get("result") or []:
            findings.append(
                Finding(
                    provider=self.name,
                    category="leaks",
                    title="BreachDirectory record",
                    severity=Severity.CRITICAL if entry.get("password") else Severity.HIGH,
                    data={
                        "email": entry.get("email"),
                        "username": entry.get("username"),
                        "password": entry.get("password"),
                        "sha1": entry.get("sha1"),
                        "hash": entry.get("hash"),
                        "sources": entry.get("sources"),
                    },
                )
            )
        return findings
