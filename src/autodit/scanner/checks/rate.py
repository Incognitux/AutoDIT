"""RATE-001: Rate-Limit Probing check."""

from typing import ClassVar

import requests

from autodit.models import Endpoint, Evidence, Finding, ScanConfig, Severity
from autodit.scanner.base_check import BaseCheck, CheckRegistry
from autodit.scanner.http_client import SafeHttpClient, redact_secrets

BURST_LIMIT = 50


@CheckRegistry.register
class RateLimitCheck(BaseCheck):
    """RATE-001: Tests for missing rate limiting with a bounded request burst."""

    check_id: ClassVar[str] = "RATE-001"
    name: ClassVar[str] = "Rate-Limit Probing"
    description: ClassVar[str] = (
        "Sends a bounded burst of requests to verify enforcement of rate limits (HTTP 429)."
    )
    remediation: ClassVar[str] = (
        "Implement rate limiting on sensitive routes using token bucket or sliding window algorithms."
    )

    def run(self, endpoint: Endpoint, config: ScanConfig) -> list[Finding]:
        """Send a bounded burst of requests to test for rate-limit throttling."""
        findings: list[Finding] = []
        client = SafeHttpClient(allow_remote=config.allow_remote, timeout=config.timeout)
        url = f"{config.target_url.rstrip('/')}/{endpoint.path.lstrip('/')}"

        rate_limit_enforced = False
        last_status = 0
        last_body = ""

        try:
            for _ in range(BURST_LIMIT):
                response = client.request(endpoint.method, url)
                last_status = response.status_code
                last_body = response.text
                if response.status_code == 429:
                    rate_limit_enforced = True
                    break

            if not rate_limit_enforced and last_status in (200, 401, 403):
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        endpoint=f"{endpoint.method} {endpoint.path}",
                        severity=Severity.HIGH,
                        title="Missing Rate Limiting Detected",
                        description=f"Server accepted {BURST_LIMIT} rapid requests without HTTP 429 status.",
                        evidence=Evidence(
                            request_method=endpoint.method,
                            request_url=url,
                            response_status=last_status,
                            response_body_excerpt=redact_secrets(last_body[:200]),
                        ),
                        remediation=self.remediation,
                    )
                )
        except (requests.RequestException, ValueError):
            return findings

        return findings
