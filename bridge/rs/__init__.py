"""Resource Server primitives.

The Resource Server is the third independent enforcement layer in the
wiki's three-layer architecture: Vault mints, bridge cannot alter, RS
validates and executes. ``JwtResourceServer`` is the executable
counterpart that makes that claim demonstrable.

See ``decisions/a2a-mcp-bridge-architecture`` for the component model
and ``decisions/a2a-mcp-bridge-design-rationale`` for the three-tier
graduation.
"""
from bridge.rs.jwt_resource_server import (
    JwtResourceServer,
    RsError,
    RsOutcome,
    RsRejected,
    RsSuccess,
)

__all__ = [
    "JwtResourceServer",
    "RsError",
    "RsOutcome",
    "RsRejected",
    "RsSuccess",
]
