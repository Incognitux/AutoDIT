"""Integration tests asserting zero findings against hardened routes."""

from unittest.mock import MagicMock, patch

from autodit.models import Endpoint, ScanConfig
from autodit.scanner.checks.auth import AuthCheck
from autodit.scanner.checks.data import DataExposureCheck
from autodit.scanner.checks.rate import RateLimitCheck


def test_auth_check_on_hardened_dashboard() -> None:
    endpoint = Endpoint(
        method="GET",
        path="/api/v1/hardened/admin/dashboard",
        auth_required=True,
    )
    config = ScanConfig(target_url="http://127.0.0.1:5050")

    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.text = '{"error": "Unauthorized"}'

    with patch("autodit.scanner.http_client.requests.Session.request", return_value=mock_resp):
        check = AuthCheck()
        findings = check.run(endpoint, config)

    # Hardened route rejects unauthenticated request, producing ZERO findings
    assert findings == []


def test_data_exposure_on_hardened_user_profile() -> None:
    endpoint = Endpoint(
        method="GET",
        path="/api/v1/hardened/users/{user_id}",
        auth_required=False,
    )
    config = ScanConfig(target_url="http://127.0.0.1:5050")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = (
        '{"id": 1, "username": "geralt", "email": "geralt@example.com", "role": "user"}'
    )

    with patch("autodit.scanner.http_client.requests.Session.request", return_value=mock_resp):
        check = DataExposureCheck()
        findings = check.run(endpoint, config)

    # Hardened payload contains no sensitive leaks, producing ZERO findings
    assert findings == []


def test_rate_limit_on_hardened_endpoint() -> None:
    endpoint = Endpoint(
        method="POST",
        path="/api/v1/hardened/login",
        auth_required=False,
    )
    config = ScanConfig(target_url="http://127.0.0.1:5050")

    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.text = '{"error": "Too Many Requests"}'

    with patch("autodit.scanner.http_client.requests.Session.request", return_value=mock_resp):
        check = RateLimitCheck()
        findings = check.run(endpoint, config)

    # 429 returned triggers rate limit enforcement, producing ZERO findings
    assert findings == []
