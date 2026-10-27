"""Render scan results as JSON, CSV, Markdown or standalone HTML."""

from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path

from osintx.models import ScanResult

SEVERITY_COLORS = {
    "critical": "#b91c1c",
    "high": "#dc2626",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#6b7280",
}

def to_json(result: ScanResult) -> str:
    return json.dumps(
        {
            "id": result.id,
            "target": result.target,
            "target_type": result.target_type.value,
            "status": result.status.value,
            "created_at": result.created_at,
            "stats": result.stats(),
            "findings": [
                {
                    "provider": f.provider,
                    "category": f.category,
                    "title": f.title,
                    "severity": f.severity.value,
                    "url": f.url,
                    "data": f.data,
                }
                for f in result.sorted_findings()
            ],
        },
        indent=2,
        ensure_ascii=False,
        default=str,
    )

def to_csv(result: ScanResult) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["severity", "category", "provider", "title", "url", "data"])
    for finding in result.sorted_findings():
        writer.writerow(
            [
                finding.severity.value,
                finding.category,
                finding.provider,
                finding.title,
                finding.url or "",
                json.dumps(finding.data, ensure_ascii=False, default=str),
            ]
        )
    return buffer.getvalue()

def to_markdown(result: ScanResult) -> str:
    lines = [
        f"# OSINTX report — `{result.target}`",
        "",
        f"- **Type:** {result.target_type.value}",
        f"- **Scan ID:** `{result.id}`",
        f"- **Created:** {result.created_at}",
        f"- **Findings:** {len(result.findings)}",
        "",
        "## Summary",
        "",
    ]
    for severity, count in sorted(result.stats()["by_severity"].items()):
        lines.append(f"- **{severity}**: {count}")
    lines += ["", "## Findings", ""]
    for finding in result.sorted_findings():
        lines.append(f"### [{finding.severity.value.upper()}] {finding.title}")
        lines.append(f"- Provider: `{finding.provider}`")
        if finding.url:
            lines.append(f"- URL: {finding.url}")
        if finding.data:
            lines.append("