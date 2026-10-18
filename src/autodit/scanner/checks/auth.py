"""AUTH-001: Multi-Role State Simulation check."""

from typing import ClassVar

import requests

from autodit.models import Endpoint, Evidence, Finding, ScanConfig, Severity
from autodit.scanner.base_check import BaseCheck, CheckRegistry
from autodit.scanner.http_client import SafeHttpClient, redact_secrets


@CheckRegistry.register
class AuthCheck(BaseCheck):
    """AUTH-001: Validates enforcement of authentication across endpoints."""

    check_id: ClassVar[str] = "AUTH-001"
    name: ClassVar[str] = "Multi-Role State Simulation"
    description: ClassVar[str] = (
        "Replays endpoints without authentication tokens to detect broken authentication."
    )
    remediation: ClassVar[str] = (
        "Enforce strict authentication middleware and validate tokens on all protected routes."
    )

    def run(self, endpoint: Endpoint, config: ScanConfig) -> list[Finding]:
        """Check if an endpoint expecting authentication is accessible without credentials."""
        findings: list[Finding] = []
        if not endpoint.auth_required:
            return findings

        client = SafeHttpClient(allow_remote=config.allow_remote, timeout=config.timeout)
        url = f"{config.target_url.rstrip('/')}/{endpoint.path.lstrip('/')}"

        try:
            # Intentionally omit credentials to test for unauthenticated access
            response = client.request(endpoint.method, url)
            if response.status_code == 200:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        endpoint=f"{endpoint.method} {endpoint.path}",
                        severity=Severity.HIGH,
                        title="Broken Authentication Detected",
                        description="Protected endpoint accessible without authorization credentials.",
                        evidence=Evidence(
                            request_method=endpoint.method,
                            request_url=url,
                            response_status=response.status_code,
                            response_body_excerpt=redact_secrets(response.text[:200]),
                        ),
                        remediation=self.remediation,
                    )
                )
        except (requests.RequestException, ValueError):
            return findings

        return findings
