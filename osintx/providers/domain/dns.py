"""DNS record enumeration via Google DoH."""

from __future__ import annotations

import asyncio

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

DOH = "https://dns.google/resolve"
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA")

class DnsProvider(BaseProvider):
    meta = ProviderMeta(
        name="dns",
        category="domain",
        description="DNS record enumeration (A, MX, NS, TXT, CNAME, SOA, CAA)",
        targets=("domain",),
        rate=4.0,
        burst=4,
        timeout=30.0,
    )

    async def _query(self, domain: str, rtype: str) -> tuple[str, list[str]]:
        try:
            response = await self.ctx.http.get(
                DOH,
                params={"name": domain, "type": rtype},
                headers={"Accept": "application/json"},
                allow_status=(200, 400, 429),
            )
        except Exception:
            return rtype, []
        if response.status_code != 200:
            return rtype, []
        payload = response.json() or {}
        answers = payload.get("Answer") or []
        return rtype, [str(a.get("data")) for a in answers if a.get("data")]

    async def run(self, target: Target) -> list[Finding]:
        results = await asyncio.gather(*(self._query(target.value, t) for t in RECORD_TYPES))
        findings: list[Finding] = []
        for rtype, values in results:
            if not values:
                continue
            severity = Severity.MEDIUM if rtype == "TXT" else Severity.INFO
            findings.append(
                Finding(
                    provider=self.name,
                    category="domain",
                    title=f"{rtype} records for {target.value}",
                    severity=severity,
                    data={"type": rtype, "values": values},
                )
            )
        return findings
