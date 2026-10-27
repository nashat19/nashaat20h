"""Pastebin recent-paste scraping for the target."""

from __future__ import annotations

import re

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

PASTE_RE = re.compile(r'href="/([A-Za-z0-9]{8})"')

class PastesProvider(BaseProvider):
    meta = ProviderMeta(
        name="pastes",
        category="dorks",
        description="Pastebin search for the target",
        targets=("email", "username", "phone", "domain"),
        rate=0.5,
        burst=1,
        timeout=25.0,
    )

    async def run(self, target: Target) -> list[Finding]:
        response = await self.ctx.http.get(
            "https://pastebin.com/search",
            params={"q": target.value},
            allow_status=(200, 429),
        )
        if response.status_code != 200:
            return []
        ids = list(dict.fromkeys(PASTE_RE.findall(response.text)))[:25]
        return [
            Finding(
                provider=self.name,
                category="dorks",
                title=f"Pastebin paste: {paste_id}",
                severity=Severity.LOW,
                url=f"https://pastebin.com/{paste_id}",
                data={"paste_id": paste_id},
            )
            for paste_id in ids
        ]
