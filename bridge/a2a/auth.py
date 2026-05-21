import os
from pathlib import Path

from starlette.requests import Request

from bridge.a2a.sdk_compat import CallContextBuilder, ServerCallContext
from bridge.auth.hmac import (
    SCOPES,
    CallerIdentity,
    TokenStore,
    _token_hash,
    caller_from_token,
)

__all__ = [
    "SCOPES",
    "CallerIdentity",
    "TokenStore",
    "_token_hash",
    "caller_from_token",
    "BearerTokenCallContextBuilder",
    "default_token_file",
    "default_a2a_secret",
]


class BearerTokenCallContextBuilder(CallContextBuilder):
    """Extract Bearer token from Authorization header into ServerCallContext.state."""

    def __init__(self, store: TokenStore, secret: str) -> None:
        self._store = store
        self._secret = secret

    # Validation is deliberately deferred to the executor (_is_authenticated).
    # This builder only extracts the raw token for the executor to verify.
    def build(self, request: Request) -> ServerCallContext:
        auth = request.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else None
        return ServerCallContext(state={"bearer_token": token or None})


def default_token_file() -> Path:
    return Path(
        os.environ.get("BRIDGE_A2A_TOKEN_FILE", Path.home() / ".bridge_a2a_tokens.json")
    )


def default_a2a_secret() -> str:
    s = os.environ.get("BRIDGE_A2A_SECRET", "")
    if not s:
        raise EnvironmentError("BRIDGE_A2A_SECRET is required for A2A token operations")
    return s
