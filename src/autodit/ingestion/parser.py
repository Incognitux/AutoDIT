"""OpenAPI 3.x validation and parsing."""

from pathlib import Path
from typing import Any

import yaml

from autodit.models import Endpoint

try:
    from openapi_spec_validator import validate
except ImportError:  # pragma: no cover
    validate = None  # type: ignore[assignment]


def parse_openapi_spec(spec_path: Path | str) -> list[Endpoint]:
    """Validate and parse an OpenAPI 3.x spec file into a list of Endpoint models."""
    path = Path(spec_path)
    with path.open("r", encoding="utf-8") as f:
        spec: dict[str, Any] = yaml.safe_load(f)

    if validate is not None:
        validate(spec)

    endpoints: list[Endpoint] = []
    paths: dict[str, Any] = spec.get("paths", {})
    http_methods = ["get", "post", "put", "patch", "delete", "options", "head"]

    for path_str, path_item in sorted(paths.items()):
        if not isinstance(path_item, dict):
            continue
        for method in http_methods:
            if method in path_item:
                op = path_item[method]
                if not isinstance(op, dict):
                    continue
                auth_required = "security" in op or "security" in spec
                endpoints.append(
                    Endpoint(
                        method=method.upper(),
                        path=path_str,
                        summary=op.get("summary", ""),
                        parameters=op.get("parameters", []),
                        auth_required=auth_required,
                        response_schemas=op.get("responses", {}),
                    )
                )

    return sorted(endpoints, key=lambda e: (e.path, e.method))
