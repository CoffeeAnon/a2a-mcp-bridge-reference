# bridge/a2a/tokens_cli.py
"""bridge a2a-token {issue,list,revoke} admin commands."""
import typer
from typing import Annotated, Optional

from bridge.a2a.auth import TokenStore, default_a2a_secret, default_token_file

a2a_token_app = typer.Typer(
    name="a2a-token",
    help="Manage A2A bearer tokens for the agent.",
    no_args_is_help=True,
)


def _get_store(token_file: str | None) -> TokenStore:
    path = token_file or str(default_token_file())
    return TokenStore(path)


def _get_secret() -> str:
    try:
        return default_a2a_secret()
    except EnvironmentError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1) from e


@a2a_token_app.command("issue")
def issue(
    scopes: Annotated[str, typer.Option("--scopes", help="Comma-separated: tasks.read,tasks.write")] = "tasks.read",
    label: Annotated[str, typer.Option("--label", help="Human-readable label for this token")] = "",
    token_file: Annotated[Optional[str], typer.Option("--token-file", help="Path to token store JSON")] = None,
):
    """Issue a new bearer token and print it. This is the only time the raw token is shown."""
    scope_list = [s.strip() for s in scopes.split(",") if s.strip()]
    store = _get_store(token_file)
    secret = _get_secret()
    try:
        token = store.issue(scope_list, label or "(no label)", secret)
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)
    typer.echo(token)


@a2a_token_app.command("list")
def list_tokens(
    token_file: Annotated[Optional[str], typer.Option("--token-file")] = None,
):
    """List all issued tokens (hash prefix, scopes, label)."""
    store = _get_store(token_file)
    entries = store.list()
    if not entries:
        typer.echo("(no tokens issued)")
        return
    for e in entries:
        typer.echo(f"{e['hash_prefix']}...  {e['scopes']}  {e['label']}")


@a2a_token_app.command("revoke")
def revoke(
    token: Annotated[str, typer.Argument(help="Raw bearer token to revoke")],
    token_file: Annotated[Optional[str], typer.Option("--token-file")] = None,
):
    """Revoke a bearer token by its raw value."""
    store = _get_store(token_file)
    secret = _get_secret()
    if store.revoke(token, secret):
        typer.echo("Token revoked.")
    else:
        typer.echo("Token not found.", err=True)
        raise typer.Exit(1)
