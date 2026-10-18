"""Tests for core typed models."""

from autodit.models import Endpoint, Evidence, Finding, ScanConfig, Severity


def test_severity_values() -> None:
    assert Severity.LOW.value == "LOW"
    assert Severity.MEDIUM.value == "MEDIUM"
    assert Severity.HIGH.value == "HIGH"
    assert Severity.CRITICAL.value == "CRITICAL"


def test_endpoint_instantiation() -> None:
    endpoint = Endpoint(method="GET", path="/api/v1/health")
    assert endpoint.method == "GET"
    assert endpoint.path == "/api/v1/health"
    assert not endpoint.auth_required
    assert endpoint.parameters == []


def test_evidence_and_finding() -> None:
    evidence = Evidence(
        request_method="GET",
        request_url="http://127.0.0.1:5050/api/v1/health",
        response_status=200,
        response_body_excerpt='{"status": "healthy"}',
    )
    finding = Finding(
        check_id="AUTH-001",
        endpoint="GET /api/v1/health",
        severity=Severity.HIGH,
        title="Sample Finding",
        description="Sample Description",
        evidence=evidence,
        remediation="Fix it",
    )
    assert finding.check_id == "AUTH-001"
    assert finding.severity == Severity.HIGH
    assert finding.evidence.response_status == 200


def test_scan_config_defaults() -> None:
    config = ScanConfig(target_url="http://localhost:5050")
    assert not config.allow_remote
    assert config.timeout == 5.0
