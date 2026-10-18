"""Tests for OpenAPI spec validation and parsing."""

from pathlib import Path

from autodit.ingestion.parser import parse_openapi_spec


def test_parse_openapi_spec(sample_spec_path: Path) -> None:
    endpoints = parse_openapi_spec(sample_spec_path)
    assert len(endpoints) >= 4

    paths = [e.path for e in endpoints]
    assert "/api/v1/health" in paths
    assert "/api/v1/users/{user_id}" in paths
    assert "/api/v1/login" in paths
    assert "/api/v1/admin/dashboard" in paths

    # Verify deterministic sorting (path, method)
    sorted_tuples = [(e.path, e.method) for e in endpoints]
    assert sorted_tuples == sorted(sorted_tuples)


def test_parse_auth_requirement(sample_spec_path: Path) -> None:
    endpoints = parse_openapi_spec(sample_spec_path)
    dashboard_ep = next(e for e in endpoints if e.path == "/api/v1/admin/dashboard")
    assert dashboard_ep.auth_required is True

    health_ep = next(e for e in endpoints if e.path == "/api/v1/health")
    assert health_ep.auth_required is False
