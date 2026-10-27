"""Offline phone parsing: validity, carrier, region, timezone."""

from __future__ import annotations

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta
from osintx.utils import normalize_phone

class PhoneLocalProvider(BaseProvider):
    meta = ProviderMeta(
        name="phone-local",
        category="phone",
        description="Offline phone metadata (carrier, region, timezone)",
        targets=("phone",),
        rate=100.0,
        burst=10,
        timeout=10.0,
    )

    async def run(self, target: Target) -> list[Finding]:
        raw = normalize_phone(target.value)
        try:
            parsed = phonenumbers.parse(raw, "IQ")
        except phonenumbers.NumberParseException:
            return [
                Finding(
                    provider=self.name,
                    category="phone",
                    title="Unparseable phone number",
                    severity=Severity.INFO,
                    data={"input": target.value},
                )
            ]

        valid = phonenumbers.is_valid_number(parsed)
        findings = [
            Finding(
                provider=self.name,
                category="phone",
                title=f"Phone metadata ({'valid' if valid else 'invalid'})",
                severity=Severity.INFO if valid else Severity.LOW,
                data={
                    "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
                    "international": phonenumbers.format_number(
                        parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
                    ),
                    "national": phonenumbers.format_number(
                        parsed, phonenumbers.PhoneNumberFormat.NATIONAL
                    ),
                    "country_code": parsed.country_code,
                    "national_number": parsed.national_number,
                    "region": geocoder.description_for_number(parsed, "en"),
                    "carrier": carrier.name_for_number(parsed, "en"),
                    "timezones": list(timezone.time_zones_for_number(parsed)),
                    "line_type": str(phonenumbers.number_type(parsed)),
                    "valid": valid,
                },
            )
        ]
        return findings
