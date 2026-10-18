"""Safe HTTP client with timeouts, secret redaction, and host restrictions."""

import ipaddress
import re
from urllib.parse import urlparse

import requests

DEFAULT_TIMEOUT = 5.0
ALLOWED_LOCAL_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}

REDACT_HEADER_KEYS = {"authorization", "proxy-authorization", "token", "x-api-key"}
REDACT_PATTERNS = [
    re.compile(r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
    re.compile(r'("password"\s*:\s*")[^"]+(")', re.IGNORECASE),
]


def is_local_or_private_target(url: str) -> bool:
    """Validate whether target URL points to localhost or private RFC1918/RFC4193 addresses."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    if hostname in ALLOWED_LOCAL_HOSTNAMES or hostname.endswith((".local", ".localhost")):
        return True

    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return False


def redact_secrets(text: str) -> str:
    """Redact sensitive credentials and tokens from text excerpts."""
    redacted = text
    for pattern in REDACT_PATTERNS:
        redacted = pattern.sub(
            r"\1[REDACTED]\2" if r"\2" in pattern.pattern else r"\1[REDACTED]", redacted
        )
    return redacted


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Sanitize sensitive headers prior to logging or reporting."""
    sanitized = {}
    for key, value in headers.items():
        if key.lower() in REDACT_HEADER_KEYS:
            sanitized[key] = "[REDACTED]"
        else:
            sanitized[key] = value
    return sanitized


class SafeHttpClient:
    """HTTP client enforcing timeouts, private network defaults, and credential safety."""

    def __init__(self, allow_remote: bool = False, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.allow_remote = allow_remote
        self.timeout = timeout
        self.session = requests.Session()

    def request(
        self,
        method: str,
        url: str,
        **kwargs: object,
    ) -> requests.Response:
        """Execute HTTP request with safety checks and explicit timeouts."""
        if not self.allow_remote and not is_local_or_private_target(url):
            raise ValueError(
                f"Target '{url}' is external. Scanning remote targets requires --allow-remote."
            )

        kwargs.setdefault("timeout", self.timeout)
        return self.session.request(method, url, **kwargs)  # type: ignore[no-any-return]
