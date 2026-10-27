"""Instagram web profile info."""

from __future__ import annotations

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

class InstagramProvider(BaseProvider):
    meta = ProviderMeta(
        name="instagram",
        category="username",
        description="Instagram public profile metadata",
        targets=("username",),
        rate=0.8,
        burst=1,
        timeout=20.0,
    )

    async def run(self, target: Target) -> list[Finding]:
        response = await self.ctx.http.get(
            f"https://www.instagram.com/{target.value}/",
            headers={"Accept": "text/html"},
            allow_status=(200, 404, 429),
        )
        if response.status_code != 200:
            return []
        body = response.text
        if "Sorry, this page" in body:
            return []
        return [
            Finding(
                provider=self.name,
                category="username",
                title=f"Instagram profile: @{target.value}",
                severity=Severity.LOW,
                url=f"https://instagram.com/{target.value}",
                data={"exists": True},
            )
        ]
