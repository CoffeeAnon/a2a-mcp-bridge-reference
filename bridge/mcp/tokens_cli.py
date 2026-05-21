"""bridge mcp-token {issue,list,revoke} admin commands."""
from typing import Annotated, Optional

import typer

from bridge.auth.hmac import TokenStore
from bridge.mcp.auth import default_mcp_secret, default_mcp_token_file

mcp_token_app = typer.Typer(
    name="mcp-token",
    help="Manage MCP bearer tokens for the MCP server.",
    no_args_is_help=True,
)


def _get_store(token_file: str | None) -> TokenStore:
    return TokenStore(token_file or str(default_mcp_token_file()))


def _get_secret() -> str:
    try:
        return default_mcp_secret()
    except EnvironmentError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1) from e


@mcp_token_app.command("issue")
def issue(
    label: Annotated[str, typer.Option("--label", help="Human-readable label")] = "",
    token_file: Annotated[Optional[str], typer.Option("--token-file")] = None,
):
    """Issue a new MCP bearer token. Token is shown once; record it now."""
    store = _get_store(token_file)
    secret = _get_secret()
    # MCP doesn't use scopes; pass tasks.read as the canonical no-op scope.
    token = store.issue(["tasks.read"], label or "(no label)", secret)
    typer.echo(token)


@mcp_token_app.command("list")
def list_tokens(
    token_file: Annotated[Optional[str], typer.Option("--token-file")] = None,
):
    """List all issued MCP tokens (hash prefix + label + revoked status)."""
    store = _get_store(token_file)
    entries = store.list()
    if not entries:
        typer.echo("(no tokens issued)")
        return
    for e in entries:
        revoked = " [REVOKED]" if e.get("revoked") else ""
        typer.echo(f"{e['hash_prefix']}...  {e['label']}{revoked}")


@mcp_token_app.command("revoke")
def revoke(
    token: Annotated[str, typer.Argument(help="Raw bearer token to revoke")],
    token_file: Annotated[Optional[str], typer.Option("--token-file")] = None,
):
    """Revoke an MCP bearer token."""
    store = _get_store(token_file)
    secret = _get_secret()
    if store.revoke(token, secret):
        typer.echo("Token revoked.")
    else:
        typer.echo("Token not found or already revoked.", err=True)
        raise typer.Exit(1)
