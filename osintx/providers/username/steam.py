"""Steam vanity URL resolver."""

from __future__ import annotations

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

class SteamProvider(BaseProvider):
    meta = ProviderMeta(
        name="steam",
        category="username",
        description="Steam vanity URL resolution",
        targets=("username",),
        rate=1.0,
        burst=1,
        timeout=20.0,
    )

    async def run(self, target: Target) -> list[Finding]:
        response = await self.ctx.http.get(
            "https://api.steampowered.com/ISteamUser/ResolveVanityURL/v1/",
            params={"key": "", "vanityurl": target.value},
            allow_status=(200, 403, 429),
        )
        if response.status_code != 200:
            return []
        payload = response.json() or {}
        data = payload.get("response") or {}
        if data.get("success") != 1:
            return []
        steam_id = data.get("steamid")
        return [
            Finding(
                provider=self.name,
                category="username",
                title=f"Steam account resolved: {steam_id}",
                severity=Severity.LOW,
                url=f"https://steamcommunity.com/profiles/{steam_id}",
                data={"steam_id": steam_id, "vanity": target.value},
            )
        ]
