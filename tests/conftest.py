"""Pytest fixtures and shared configuration."""

from pathlib import Path

import pytest

from autodit.models import Endpoint, Evidence, Finding, ScanConfig, Severity


@pytest.fixture
def repo_root() -> Path:
    """Return the repository root path."""
    return Path(__file__).parent.parent


@pytest.fixture
def sample_spec_path(repo_root: Path) -> Path:
    """Return path to vuln_api openapi.yaml."""
    return repo_root / "vuln_api" / "openapi.yaml"


@pytest.fixture
def sample_endpoint() -> Endpoint:
    """Return a sample Endpoint object."""
    return Endpoint(
        method="GET",
        path="/api/v1/users/{user_id}",
        summary="Get user profile",
        auth_required=False,
    )


@pytest.fixture
def sample_finding() -> Finding:
    """Return a sample Finding object."""
    return Finding(
        check_id="DATA-001",
        endpoint="GET /api/v1/users/{user_id}",
        severity=Severity.HIGH,
        title="Excessive Data Exposure Detected",
        description="Sensitive data patterns found in payload.",
        evidence=Evidence(
            request_method="GET",
            request_url="http://localhost:5050/api/v1/users/1",
            response_status=200,
            response_body_excerpt='{"ssn": "123-45-6789"}',
        ),
        remediation="Omit internal fields and PII.",
    )


@pytest.fixture
def scan_config() -> ScanConfig:
    """Return default ScanConfig."""
    return ScanConfig(target_url="http://127.0.0.1:5050", allow_remote=False)
