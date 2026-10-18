"""Unit tests for heuristic data fingerprints with positive and negative samples."""

import pytest

from autodit.scanner.fingerprints import find_sensitive_matches, inspect_payload_for_sensitive_keys


@pytest.mark.parametrize(
    ("sample", "expected_match"),
    [
        ("SSN number is 123-45-6789 here", "ssn"),
        ("Hash: $2b$12$e8kPj91gK.9uL128.9s1abcde12345678901234567890123", "password_hash"),
        ("Internal db identifier usr_sec_00984a123 detected", "internal_db_id"),
    ],
)
def test_fingerprints_positive_matches(sample: str, expected_match: str) -> None:
    matches = find_sensitive_matches(sample)
    assert expected_match in matches


@pytest.mark.parametrize(
    "clean_sample",
    [
        "Regular username is john_doe",
        "Phone number format 1234567890",
        "Order ID 984712 and zip 10001",
        "Public API status OK",
    ],
)
def test_fingerprints_negative_matches(clean_sample: str) -> None:
    matches = find_sensitive_matches(clean_sample)
    assert matches == []


def test_inspect_payload_keys() -> None:
    payload = '{"username": "geralt", "password_hash": "secret", "ssn": "000-00-0000"}'
    detected = inspect_payload_for_sensitive_keys(payload)
    assert "password_hash" in detected
    assert "ssn" in detected

    clean_payload = '{"username": "geralt", "email": "geralt@example.com"}'
    clean_detected = inspect_payload_for_sensitive_keys(clean_payload)
    assert clean_detected == []
