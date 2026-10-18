"""Table-driven unit tests for threat prioritization matrix."""

import pytest

from autodit.models import Evidence, Finding, Severity
from autodit.reporting.prioritizer import compute_compound_severity, prioritize_findings


@pytest.mark.parametrize(
    ("check_ids", "expected_severity"),
    [
        ({"AUTH-001", "DATA-001", "RATE-001"}, Severity.CRITICAL),
        ({"AUTH-001"}, Severity.HIGH),
        ({"AUTH-001", "RATE-001"}, Severity.HIGH),
        ({"DATA-001"}, Severity.MEDIUM),
        ({"DATA-001", "RATE-001"}, Severity.MEDIUM),
        ({"RATE-001"}, Severity.LOW),
        (set(), Severity.LOW),
    ],
)
def test_compound_severity_matrix(check_ids: set[str], expected_severity: Severity) -> None:
    severity = compute_compound_severity(check_ids)
    assert severity == expected_severity


def test_prioritize_findings_sorting() -> None:
    dummy_evidence = Evidence(
        request_method="GET",
        request_url="http://localhost:5050/test",
        response_status=200,
    )

    finding_low = Finding(
        check_id="RATE-001",
        endpoint="POST /api/v1/login",
        severity=Severity.LOW,
        title="Rate Limit",
        description="Missing rate limit",
        evidence=dummy_evidence,
        remediation="Throttle requests",
    )
    finding_high = Finding(
        check_id="AUTH-001",
        endpoint="GET /api/v1/admin/dashboard",
        severity=Severity.HIGH,
        title="Broken Auth",
        description="Missing auth",
        evidence=dummy_evidence,
        remediation="Enforce auth",
    )

    prioritized = prioritize_findings([finding_low, finding_high])
    # High should come before Low
    assert prioritized[0].severity == Severity.HIGH
    assert prioritized[1].severity == Severity.LOW
