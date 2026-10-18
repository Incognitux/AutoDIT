"""Role simulation contexts and identity definitions."""

from dataclasses import dataclass, field


@dataclass
class RoleContext:
    """Authentication and identity context for role simulation."""

    name: str
    token: str | None = None
    headers: dict[str, str] = field(default_factory=dict)

    def get_headers(self) -> dict[str, str]:
        """Generate headers including Authorization if token exists."""
        merged = dict(self.headers)
        if self.token:
            merged["Authorization"] = f"Bearer {self.token}"
        return merged
