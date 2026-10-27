"""Have I Been Pwned — breach exposure by email/account."""

from __future__ import annotations

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

API = "https://haveibeenpwned.com/api/v3"

class HIBPProvider(BaseProvider):
    meta = ProviderMeta(
        name="hibp",
        category="leaks",
        description="Have I Been Pwned breach lookup",
        targets=("email", "username"),
        requires_key=True,
        key_attr="hibp_key",
        rate=1.5,
        burst=2,
        timeout=25.0,
    )

    async def run(self, target: Target) -> list[Finding]:
        headers = {
            "hibp-api-key": self.ctx.config.hibp_key,
            "User-Agent": "OSINTX/1.0",
        }
        response = await self.ctx.http.get(
            f"{API}/breachedaccount/{target.value}",
            headers=headers,
            params={"truncateResponse": "false"},
            allow_status=(200, 404, 401, 403, 429),
        )
        if response.status_code == 404:
            return []
        if response.status_code in {401, 403}:
            raise RuntimeError("invalid HIBP API key")
        if response.status_code == 429:
            raise RuntimeError("HIBP rate limit exceeded")
        breaches = response.json() or []

        findings: list[Finding] = []
        for breach in breaches:
            classes = breach.get("DataClasses") or []
            severity = Severity.HIGH if "Passwords" in classes else Severity.MEDIUM
            findings.append(
                Finding(
                    provider=self.name,
                    category="leaks",
                    title=f"Breach: {breach.get('Title') or breach.get('Name')}",
                    severity=severity,
                    url=f"https://haveibeenpwned.com/PwnedWebsites#{breach.get('Name')}",
                    data={
                        "breach": breach.get("Name"),
                        "domain": breach.get("Domain"),
                        "date": breach.get("BreachDate"),
                        "pwn_count": breach.get("PwnCount"),
                        "data_classes": classes,
                        "verified": breach.get("IsVerified"),
                        "sensitive": breach.get("IsSensitive"),
                    },
                )
            )
        return findings
