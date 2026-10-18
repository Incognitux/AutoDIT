"""Base check definition and check registry."""

from abc import ABC, abstractmethod
from typing import ClassVar

from autodit.models import Endpoint, Finding, ScanConfig


class BaseCheck(ABC):
    """Abstract base class for all scanner checks."""

    check_id: ClassVar[str]
    name: ClassVar[str]
    description: ClassVar[str]
    remediation: ClassVar[str]

    @abstractmethod
    def run(self, endpoint: Endpoint, config: ScanConfig) -> list[Finding]:
        """Execute check against endpoint and return any findings with evidence."""


class CheckRegistry:
    """Registry maintaining available check classes."""

    _registry: ClassVar[dict[str, type[BaseCheck]]] = {}

    @classmethod
    def register(cls, check_cls: type[BaseCheck]) -> type[BaseCheck]:
        """Register a check class by check_id."""
        cls._registry[check_cls.check_id] = check_cls
        return check_cls

    @classmethod
    def get_all(cls) -> list[type[BaseCheck]]:
        """Return all registered checks sorted deterministically by check_id."""
        return [cls._registry[key] for key in sorted(cls._registry.keys())]

    @classmethod
    def get(cls, check_id: str) -> type[BaseCheck] | None:
        """Retrieve a registered check by its ID."""
        return cls._registry.get(check_id)
