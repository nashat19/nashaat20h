"""Passive dork vector generator (no network)."""

from __future__ import annotations

from urllib.parse import quote_plus

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

TEMPLATES = {
    "email": [
        '"{t}" filetype:pdf',
        '"{t}" filetype:xlsx',
        '"{t}" site:pastebin.com',
        '"{t}" site:github.com',
        '"{t}" "password"',
        '"{t}" "api_key"',
        '"{t}" ext:sql',
        '"{t}" ext:env',
    ],
    "username": [
        '"{t}" site:github.com',
        '"{t}" site:pastebin.com',
        '"{t}" "password"',
        '"{t}" "email"',
        '"{t}" inurl:profile',
        '"{t}" ext:sql',
    ],
    "phone": [
        '"{t}"',
        '"{t}" site:facebook.com',
        '"{t}" site:linkedin.com',
        '"{t}" "whatsapp"',
        '"{t}" filetype:pdf',
    ],
    "domain": [
        "site:{t} ext:env",
        "site:{t} ext:sql",
        "site:{t} ext:log",
        "site:{t} inurl:admin",
        "site:{t} intitle:index.of",
        "site:{t} ext:bak",
        "site:{t} ext:git",
        "site:{t} inurl:api",
    ],
}

ENGINES = {
    "Google": "https://www.google.com/search?q={q}",
    "Bing": "https://www.bing.com/search?q={q}",
    "DuckDuckGo": "https://duckduckgo.com/?q={q}",
    "GitHub": "https://github.com/search?q={q}&type=code",
    "Pastebin": "https://pastebin.com/search?q={q}",
}

class DorkGeneratorProvider(BaseProvider):
    meta = ProviderMeta(
        name="dorks",
        category="dorks",
        description="Generate ready-to-click dork vectors",
        targets=("email", "username", "phone", "domain"),
        rate=100.0,
        burst=10,
        timeout=10.0,
    )

    async def run(self, target: Target) -> list[Finding]:
        templates = TEMPLATES.get(target.type.value, [])
        findings: list[Finding] = []
        for template in templates:
            query = template.format(t=target.value)
            encoded = quote_plus(query)
            for engine, url_template in ENGINES.items():
                findings.append(
                    Finding(
                        provider=self.name,
                        category="dorks",
                        title=f"{engine} dork: {query}",
                        severity=Severity.INFO,
                        url=url_template.format(q=encoded),
                        data={"engine": engine, "query": query},
                    )
                )
        return findings
