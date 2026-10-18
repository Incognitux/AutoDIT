"""DATA-001: Heuristic Data Fingerprinting check."""

from typing import ClassVar

import requests

from autodit.models import Endpoint, Evidence, Finding, ScanConfig, Severity
from autodit.scanner.base_check import BaseCheck, CheckRegistry
from autodit.scanner.fingerprints import find_sensitive_matches, inspect_payload_for_sensitive_keys
from autodit.scanner.http_client import SafeHttpClient, redact_secrets


@CheckRegistry.register
class DataExposureCheck(BaseCheck):
    """DATA-001: Inspects responses for excessive data exposure."""

    check_id: ClassVar[str] = "DATA-001"
    name: ClassVar[str] = "Heuristic Data Fingerprinting"
    description: ClassVar[str] = (
        "Inspects JSON response bodies for sensitive fields, tokens, or PII leaking beyond declared schemas."
    )
    remediation: ClassVar[str] = (
        "Filter and serialize response models strictly to omit internal fields, hashes, and PII."
    )

    def run(self, endpoint: Endpoint, config: ScanConfig) -> list[Finding]:
        """Perform heuristic data fingerprinting on endpoint responses."""
        findings: list[Finding] = []
        client = SafeHttpClient(allow_remote=config.allow_remote, timeout=config.timeout)

        # Build URL resolving simple path parameters (e.g. {user_id} -> 1)
        path = endpoint.path.replace("{user_id}", "1").replace("{id}", "1")
        url = f"{config.target_url.rstrip('/')}/{path.lstrip('/')}"

        try:
            response = client.request(endpoint.method, url)
            if response.status_code == 200:
                pattern_matches = find_sensitive_matches(response.text)
                key_matches = inspect_payload_for_sensitive_keys(response.text)
                all_matches = sorted(set(pattern_matches + key_matches))

                if all_matches:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            endpoint=f"{endpoint.method} {endpoint.path}",
                            severity=Severity.HIGH,
                            title="Excessive Data Exposure Detected",
                            description=(
                                f"Sensitive data patterns/keys ({', '.join(all_matches)}) detected in response payload."
                            ),
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
