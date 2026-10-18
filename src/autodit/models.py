"""Core typed data models for AutoDIT."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Endpoint:
    method: str
    path: str
    summary: str = ""
    parameters: list[dict[str, Any]] = field(default_factory=list)
    auth_required: bool = False
    response_schemas: dict[str, Any] = field(default_factory=dict)


@dataclass
class Evidence:
    request_method: str
    request_url: str
    request_headers: dict[str, str] = field(default_factory=dict)
    response_status: int = 0
    response_body_excerpt: str = ""


@dataclass
class Finding:
    check_id: str
    endpoint: str
    severity: Severity
    title: str
    description: str
    evidence: Evidence
    remediation: str


@dataclass
class ScanConfig:
    target_url: str
    spec_path: Path | None = None
    allow_remote: bool = False
    timeout: float = 5.0
