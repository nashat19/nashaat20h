"""Telegram public page metadata."""

from __future__ import annotations

import re

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

TITLE_RE = re.compile(r'<meta property="og:title" content="([^"]+)"')
DESC_RE = re.compile(r'<meta property="og:description" content="([^"]+)"')

class TelegramProvider(BaseProvider):
    meta = ProviderMeta(
        name="telegram",
        category="username",
        description="Telegram public channel/user page",
        targets=("username",),
        rate=1.0,
        burst=1,
        timeout=20.0,
    )

    async def run(self, target: Target) -> list[Finding]:
        response = await self.ctx.http.get(
            f"https://t.me/{target.value}",
            allow_status=(200, 404, 429),
        )
        if response.status_code != 200:
            return []
        body = response.text
        if "tgme_page_title" not in body:
            return []
        title = TITLE_RE.search(body)
        desc = DESC_RE.search(body)
        return [
            Finding(
                provider=self.name,
                category="username",
                title=f"Telegram: {title.group(1) if title else target.value}",
                severity=Severity.LOW,
                url=f"https://t.me/{target.value}",
                data={
                    "display_name": title.group(1) if title else None,
                    "description": desc.group(1) if desc else None,
                },
            )
        ]
