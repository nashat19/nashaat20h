"""crt.sh — certificate transparency subdomain discovery."""

from __future__ import annotations

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

class CrtShProvider(BaseProvider):
    meta = ProviderMeta(
        name="crtsh",
        category="domain",
        description="Certificate Transparency subdomain enumeration",
        targets=("domain",),
        rate=0.5,
        burst=1,
        timeout=45.0,
    )

    async def run(self, target: Target) -> list[Finding]:
        response = await self.ctx.http.get(
            "https://crt.sh/",
            params={"q": f"%.{target.value}", "output": "json"},
            allow_status=(200, 404, 429, 502, 503),
        )
        if response.status_code != 200:
            return []
        try:
            rows = response.json() or []
        except ValueError:
            return []

        seen: set[str] = set()
        findings: list[Finding] = []
        for row in rows:
            for name in (row.get("name_value") or "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if not name or name in seen or not name.endswith(target.value):
                    continue
                seen.add(name)
                findings.append(
                    Finding(
                        provider=self.name,
                        category="domain",
                        title=f"Subdomain: {name}",
                        severity=Severity.LOW,
                        url=f"https://{name}",
                        data={
                            "subdomain": name,
                            "issuer": row.get("issuer_name"),
                            "not_before": row.get("not_before"),
                            "not_after": row.get("not_after"),
                        },
                    )
                )
        return findings
