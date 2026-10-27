"""Wayback Machine CDX — historical URL discovery."""

from __future__ import annotations

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

class WaybackProvider(BaseProvider):
    meta = ProviderMeta(
        name="wayback",
        category="domain",
        description="Wayback Machine historical URL discovery",
        targets=("domain",),
        rate=0.5,
        burst=1,
        timeout=45.0,
    )

    async def run(self, target: Target) -> list[Finding]:
        response = await self.ctx.http.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"{target.value}/*",
                "output": "json",
                "fl": "original,timestamp,statuscode,mimetype",
                "collapse": "urlkey",
                "limit": 500,
            },
            allow_status=(200, 404, 429, 502, 503),
        )
        if response.status_code != 200:
            return []
        try:
            rows = response.json() or []
        except ValueError:
            return []
        if len(rows) < 2:
            return []

        findings: list[Finding] = []
        for row in rows[1:]:
            if len(row) < 4:
                continue
            url, timestamp, status, mimetype = row[0], row[1], row[2], row[3]
            findings.append(
                Finding(
                    provider=self.name,
                    category="domain",
                    title=f"Archived: {url}",
                    severity=Severity.INFO,
                    url=f"https://web.archive.org/web/{timestamp}/{url}",
                    data={
                        "original": url,
                        "timestamp": timestamp,
                        "status": status,
                        "mimetype": mimetype,
                    },
                )
            )
        return findings
