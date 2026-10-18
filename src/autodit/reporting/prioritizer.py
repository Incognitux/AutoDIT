"""Algorithmic compound threat prioritization matrix."""

from collections import defaultdict

from autodit.models import Finding, Severity

# Severity priority ordering for sorting
SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def compute_compound_severity(check_ids: set[str]) -> Severity:
    """Calculate compound severity from a set of check IDs present on a single endpoint.

    +------------------------------------------------------------------------+
    | Missing Auth + Sensitive Data Exposure + No Rate Limit => CRITICAL    |
    | Missing Auth + Standard Endpoint                       => HIGH        |
    | Authenticated + Sensitive Data Exposure                => MEDIUM      |
    | Authenticated + No Rate Limit                          => LOW         |
    +------------------------------------------------------------------------+
    """
    has_auth = "AUTH-001" in check_ids
    has_data = "DATA-001" in check_ids
    has_rate = "RATE-001" in check_ids

    if has_auth and has_data and has_rate:
        return Severity.CRITICAL
    if has_auth:
        return Severity.HIGH
    if has_data:
        return Severity.MEDIUM
    if has_rate:
        return Severity.LOW

    return Severity.LOW


def prioritize_findings(findings: list[Finding]) -> list[Finding]:
    """Group findings by endpoint, compute compound severity, and sort deterministically."""
    if not findings:
        return []

    # Group findings by endpoint
    endpoint_groups: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        endpoint_groups[finding.endpoint].append(finding)

    prioritized: list[Finding] = []

    for group in endpoint_groups.values():
        check_ids = {f.check_id for f in group}
        compound = compute_compound_severity(check_ids)

        for finding in group:
            # Upgrade finding severity to compound if compound is higher
            current_order = SEVERITY_ORDER.get(finding.severity, 3)
            compound_order = SEVERITY_ORDER.get(compound, 3)
            final_severity = compound if compound_order < current_order else finding.severity

            prioritized.append(
                Finding(
                    check_id=finding.check_id,
                    endpoint=finding.endpoint,
                    severity=final_severity,
                    title=finding.title,
                    description=finding.description,
                    evidence=finding.evidence,
                    remediation=finding.remediation,
                )
            )

    # Sort deterministically: severity (Critical -> High -> Medium -> Low), endpoint, check_id
    return sorted(
        prioritized,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.endpoint, f.check_id),
    )
