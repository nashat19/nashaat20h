"""TikTok public profile check."""

from __future__ import annotations

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

class TikTokProvider(BaseProvider):
    meta = ProviderMeta(
        name="tiktok",
        category="username",
        description="TikTok public profile check",
        targets=("username",),
        rate=0.8,
        burst=1,
        timeout=20.0,
    )

    async def run(self, target: Target) -> list[Finding]:
        response = await self.ctx.http.get(
            f"https://www.tiktok.com/@{target.value}",
            allow_status=(200, 404, 429),
        )
        if response.status_code != 200:
            return []
        if "Couldn't find this account" in response.text:
            return []
        return [
            Finding(
                provider=self.name,
                category="username",
                title=f"TikTok profile: @{target.value}",
                severity=Severity.LOW,
                url=f"https://tiktok.com/@{target.value}",
                data={"exists": True},
            )
        ]
