"""Integration tests asserting exact expected finding set against vulnerable routes."""

from unittest.mock import MagicMock, patch

from autodit.models import Endpoint, ScanConfig
from autodit.scanner.checks.auth import AuthCheck
from autodit.scanner.checks.data import DataExposureCheck
from autodit.scanner.checks.rate import RateLimitCheck


def test_auth_check_on_vulnerable_dashboard() -> None:
    endpoint = Endpoint(
        method="GET",
        path="/api/v1/admin/dashboard",
        auth_required=True,
    )
    config = ScanConfig(target_url="http://127.0.0.1:5050")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"message": "Welcome to the admin dashboard"}'

    with patch("autodit.scanner.http_client.requests.Session.request", return_value=mock_resp):
        check = AuthCheck()
        findings = check.run(endpoint, config)

    assert len(findings) == 1
    assert findings[0].check_id == "AUTH-001"
    assert "Broken Authentication" in findings[0].title


def test_data_exposure_on_vulnerable_user_profile() -> None:
    endpoint = Endpoint(
        method="GET",
        path="/api/v1/users/{user_id}",
        auth_required=False,
    )
    config = ScanConfig(target_url="http://127.0.0.1:5050")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = (
        '{"id": 1, "username": "geralt", "ssn": "123-45-6789", '
        '"password_hash": "$2b$12$e8kPj91gK.9uL128.9s1abcde12345678901234567890123"}'
    )

    with patch("autodit.scanner.http_client.requests.Session.request", return_value=mock_resp):
        check = DataExposureCheck()
        findings = check.run(endpoint, config)

    assert len(findings) == 1
    assert findings[0].check_id == "DATA-001"
    assert "Excessive Data Exposure" in findings[0].title


def test_rate_limit_on_vulnerable_login() -> None:
    endpoint = Endpoint(
        method="POST",
        path="/api/v1/login",
        auth_required=False,
    )
    config = ScanConfig(target_url="http://127.0.0.1:5050")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"token": "mock-jwt-token"}'

    with patch("autodit.scanner.http_client.requests.Session.request", return_value=mock_resp):
        check = RateLimitCheck()
        findings = check.run(endpoint, config)

    assert len(findings) == 1
    assert findings[0].check_id == "RATE-001"
    assert "Missing Rate Limiting" in findings[0].title
