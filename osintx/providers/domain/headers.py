"""HTTP security header audit."""

from __future__ import annotations

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "COOP",
    "cross-origin-embedder-policy": "COEP",
}

class HeadersProvider(BaseProvider):
    meta = ProviderMeta(
        name="headers",
        category="domain",
        description="HTTP security header audit",
        targets=("domain",),
        rate=1.0,
        burst=1,
        timeout=20.0,
    )

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for scheme in ("https", "http"):
            try:
                response = await self.ctx.http.get(
                    f"{scheme}://{target.value}",
                    allow_status=tuple(range(200, 600)),
                )
            except Exception:
                continue

            present = {h: response.headers.get(h) for h in SECURITY_HEADERS if response.headers.get(h)}
            missing = [label for h, label in SECURITY_HEADERS.items() if h not in response.headers]

            findings.append(
                Finding(
                    provider=self.name,
                    category="domain",
                    title=f"{scheme.upper()} {response.status_code} — {len(missing)} missing security headers",
                    severity=Severity.MEDIUM if missing else Severity.INFO,
                    url=f"{scheme}://{target.value}",
                    data={
                        "status": response.status_code,
                        "server": response.headers.get("server"),
                        "powered_by": response.headers.get("x-powered-by"),
                        "present": present,
                        "missing": missing,
                    },
                )
            )
            break
        return findings
