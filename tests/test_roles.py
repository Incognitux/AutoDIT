"""Unit tests for role contexts and multi-role simulation models."""

from autodit.scanner.roles import RoleContext


def test_role_context_unauthenticated() -> None:
    role = RoleContext(name="anonymous")
    headers = role.get_headers()
    assert "Authorization" not in headers


def test_role_context_with_token() -> None:
    role = RoleContext(name="user", token="jwt-token-xyz")
    headers = role.get_headers()
    assert headers.get("Authorization") == "Bearer jwt-token-xyz"


def test_role_context_merged_headers() -> None:
    role = RoleContext(
        name="admin",
        token="admin-token",
        headers={"X-Custom": "val"},
    )
    headers = role.get_headers()
    assert headers.get("Authorization") == "Bearer admin-token"
    assert headers.get("X-Custom") == "val"
