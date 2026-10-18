"""Click CLI commands and options for AutoDIT."""

from pathlib import Path

import click


@click.group()
@click.version_option()
def cli() -> None:
    """AutoDIT: Deterministic, zero-configuration API security auditing engine."""


@cli.command()
@click.argument("spec", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--target",
    default="http://localhost:8000",
    show_default=True,
    help="Target API base URL to audit.",
)
@click.option(
    "--allow-remote",
    is_flag=True,
    default=False,
    help="Explicitly permit scanning remote (non-localhost) targets.",
)
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    default=None,
    help="Output file path for the report.",
)
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["markdown", "json"], case_sensitive=False),
    default="markdown",
    show_default=True,
    help="Report output format.",
)
def scan(
    spec: Path,
    target: str,
    allow_remote: bool,
    output: Path | None,
    report_format: str,
) -> None:
    """Scan an API target against an OpenAPI specification."""
    click.echo(f"[*] Auditing target: {target} against spec: {spec}")


def main() -> None:
    """CLI entrypoint."""
    cli()
