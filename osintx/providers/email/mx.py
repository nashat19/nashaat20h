"""MX / SPF / DMARC posture for the email domain."""

from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.exception
import dns.resolver

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

class EmailMxProvider(BaseProvider):
    meta = ProviderMeta(
        name="email-mx",
        category="email",
        description="MX, SPF and DMARC records for the email domain",
        targets=("email",),
        rate=5.0,
        burst=3,
        timeout=20.0,
    )

    async def _query(self, name: str, rtype: str) -> list[str]:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 8.0
        try:
            answer = await resolver.resolve(name, rtype)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            return []
        except Exception:
            return []
        return [str(r).strip('"') for r in answer]

    async def run(self, target: Target) -> list[Finding]:
        domain = target.value.split("@", 1)[-1]
        mx, spf, dmarc = await asyncio.gather(
            self._query(domain, "MX"),
            self._query(domain, "TXT"),
            self._query(f"_dmarc.{domain}", "TXT"),
        )
        spf_records = [r for r in spf if r.lower().startswith("v=spf1")]
        findings: list[Finding] = []

        if mx:
            findings.append(
                Finding(
                    provider=self.name,
                    category="email",
                    title=f"MX records for {domain}",
                    severity=Severity.INFO,
                    data={"mx": mx},
                )
            )
        if spf_records:
            findings.append(
                Finding(
                    provider=self.name,
                    category="email",
                    title=f"SPF policy for {domain}",
                    severity=Severity.INFO,
                    data={"spf": spf_records},
                )
            )
        else:
            findings.append(
                Finding(
                    provider=self.name,
                    category="email",
                    title=f"No SPF record for {domain}",
                    severity=Severity.LOW,
                    data={"domain": domain},
                )
            )
        if dmarc:
            findings.append(
                Finding(
                    provider=self.name,
                    category="email",
                    title=f"DMARC policy for {domain}",
                    severity=Severity.INFO,
                    data={"dmarc": dmarc},
                )
            )
        else:
            findings.append(
                Finding(
                    provider=self.name,
                    category="email",
                    title=f"No DMARC record for {domain}",
                    severity=Severity.LOW,
                    data={"domain": domain},
                )
            )
        return findings
