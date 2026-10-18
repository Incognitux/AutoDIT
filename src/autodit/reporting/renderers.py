"""JSON and Markdown report formatters."""

import json

from autodit.models import Finding


def render_json(findings: list[Finding]) -> str:
    """Render findings list as formatted JSON."""
    data = [
        {
            "check_id": f.check_id,
            "endpoint": f.endpoint,
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description,
            "evidence": {
                "request_method": f.evidence.request_method,
                "request_url": f.evidence.request_url,
                "request_headers": f.evidence.request_headers,
                "response_status": f.evidence.response_status,
                "response_body_excerpt": f.evidence.response_body_excerpt,
            },
            "remediation": f.remediation,
        }
        for f in findings
    ]
    return json.dumps(data, indent=2)


def render_markdown(findings: list[Finding]) -> str:
    """Render findings list as human-readable Markdown."""
    lines = [
        "# AutoDIT Security Audit Report",
        "",
        f"Total Findings: {len(findings)}",
        "",
    ]

    if not findings:
        lines.append("No security vulnerabilities detected.")
        return "\n".join(lines)

    for f in findings:
        lines.extend(
            [
                f"### [{f.severity.value}] {f.title} (`{f.check_id}`)",
                "",
                f"- **Endpoint**: `{f.endpoint}`",
                f"- **Description**: {f.description}",
                f"- **Evidence**: HTTP {f.evidence.response_status} from `{f.evidence.request_method} {f.evidence.request_url}`",
            ]
        )
        if f.evidence.response_body_excerpt:
            lines.append(f"  > `{f.evidence.response_body_excerpt.strip()}`")
        lines.extend(
            [
                f"- **Remediation**: {f.remediation}",
                "",
            ]
        )

    return "\n".join(lines)
