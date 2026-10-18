"""Sensitive-data regex patterns and heuristic detection."""

import re

PATTERNS: dict[str, re.Pattern[str]] = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "password_hash": re.compile(r"\$2[abxy]?\$\d{2}\$[A-Za-z0-9./]{20,60}"),
    "internal_db_id": re.compile(r"\busr_sec_[0-9a-fA-F]{6,}\b"),
    "jwt_token": re.compile(r"\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b"),
}


def find_sensitive_matches(data: str) -> list[str]:
    """Scan string data for known sensitive regex matches."""
    matches = set()
    for name, pattern in PATTERNS.items():
        if pattern.search(data):
            matches.add(name)
    return sorted(matches)


def inspect_payload_for_sensitive_keys(data: str) -> list[str]:
    """Check for sensitive property keys commonly leaked in JSON payloads."""
    lowered = data.lower()
    detected = []
    for key in ["password_hash", "ssn", "internal_db_id"]:
        if f'"{key}"' in lowered or f"'{key}'" in lowered or key in lowered:
            detected.append(key)
    return sorted(set(detected))
