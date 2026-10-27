"""Reddit public profile via about.json."""

from __future__ import annotations

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

class RedditProvider(BaseProvider):
    meta = ProviderMeta(
        name="reddit",
        category="username",
        description="Reddit public profile metadata",
        targets=("username",),
        rate=1.0,
        burst=1,
        timeout=20.0,
    )

    async def run(self, target: Target) -> list[Finding]:
        response = await self.ctx.http.get(
            f"https://www.reddit.com/user/{target.value}/about.json",
            headers={"Accept": "application/json"},
            allow_status=(200, 404, 403, 429),
        )
        if response.status_code != 200:
            return []
        data = (response.json() or {}).get("data") or {}
        if not data.get("name"):
            return []
        return [
            Finding(
                provider=self.name,
                category="username",
                title=f"Reddit account: u/{data['name']}",
                severity=Severity.LOW,
                url=f"https://reddit.com/user/{data['name']}",
                data={
                    "created_utc": data.get("created_utc"),
                    "link_karma": data.get("link_karma"),
                    "comment_karma": data.get("comment_karma"),
                    "is_mod": data.get("is_mod"),
                    "verified": data.get("verified"),
                },
            )
        ]
