"""Scan orchestrator module."""

import autodit.scanner.checks  # noqa: F401 - ensure checks register
from autodit.models import Endpoint, Finding, ScanConfig
from autodit.scanner.base_check import CheckRegistry


def run_scan(endpoints: list[Endpoint], config: ScanConfig) -> list[Finding]:
    """Execute all registered checks against the parsed endpoints deterministically."""
    all_findings: list[Finding] = []
    checks = [check_cls() for check_cls in CheckRegistry.get_all()]

    # Sort endpoints deterministically by path and HTTP method
    sorted_endpoints = sorted(endpoints, key=lambda ep: (ep.path, ep.method))

    for endpoint in sorted_endpoints:
        for check in checks:
            findings = check.run(endpoint, config)
            all_findings.extend(findings)

    # Sort findings deterministically by endpoint and check ID
    return sorted(all_findings, key=lambda f: (f.endpoint, f.check_id))
