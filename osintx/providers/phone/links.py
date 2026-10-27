"""Deep-link generators for messaging platforms."""

from __future__ import annotations

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta
from osintx.utils import normalize_phone

class PhoneLinksProvider(BaseProvider):
    meta = ProviderMeta(
        name="phone-links",
        category="phone",
        description="Messaging deep links (WhatsApp, Telegram, Viber, Signal)",
        targets=("phone",),
        rate=100.0,
        burst=10,
        timeout=10.0,
    )

    async def run(self, target: Target) -> list[Finding]:
        e164 = normalize_phone(target.value)
        digits = e164.lstrip("+")
        links = {
            "WhatsApp": f"https://wa.me/{digits}",
            "Telegram": f"https://t.me/+{digits}",
            "Viber": f"viber://chat?number=%2B{digits}",
            "Signal": f"https://signal.me/#p/+{digits}",
            "Truecaller": f"https://www.truecaller.com/search/global/{digits}",
            "Sync.me": f"https://sync.me/search/?number=%2B{digits}",
        }
        return [
            Finding(
                provider=self.name,
                category="phone",
                title=f"{platform} deep link",
                severity=Severity.INFO,
                url=url,
                data={"platform": platform, "number": e164},
            )
            for platform, url in links.items()
        ]
