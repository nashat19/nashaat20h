"""Gravatar profile lookup by email hash."""

from __future__ import annotations

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta
from osintx.utils import md5

class GravatarProvider(BaseProvider):
    meta = ProviderMeta(
        name="gravatar",
        category="email",
        description="Gravatar profile existence",
        targets=("email",),
        rate=2.0,
        burst=2,
        timeout=15.0,
    )

    async def run(self, target: Target) -> list[Finding]:
        digest = md5(target.value.strip().lower())
        response = await self.ctx.http.get(
            f"https://www.gravatar.com/avatar/{digest}",
            params={"d": "404"},
            allow_status=(200, 404, 429),
        )
        if response.status_code != 200:
            return []
        profile = await self.ctx.http.get(
            f"https://www.gravatar.com/{digest}.json",
            allow_status=(200, 404, 429),
        )
        data = {}
        if profile.status_code == 200:
            entry = (profile.json() or {}).get("entry") or [{}]
            data = entry[0] if entry else {}
        return [
            Finding(
                provider=self.name,
                category="email",
                title="Gravatar profile found",
                severity=Severity.LOW,
                url=f"https://gravatar.com/{digest}",
                data={
                    "hash": digest,
                    "display_name": data.get("displayName"),
                    "about": data.get("aboutMe"),
                    "urls": [u.get("value") for u in data.get("urls") or []],
                },
            )
        ]
