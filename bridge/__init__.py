"""A2A↔MCP bridge reference implementation.

Two patterns demonstrated:

  - **Pattern 1 (orchestration)** — ``bridge.translation``: translate
    between A2A ``auth_required`` SSE events and MCP elicitation
    requests, preserving ``context_id`` continuity, ``authorization_details``
    byte-identity, and URL-mode-for-sensitive-consent.

  - **Pattern 2 (cryptographic delegation)** — ``bridge.vault``: every
    destructive action is approved by a human signing the specific
    RAR-shaped ``authorization_details`` payload. The signature drives
    the Vault to mint a single-use, action-scoped credential;
    ``bridge.rs`` validates the credential against the live request,
    independently of the Vault. Three enforcement layers.

Read ``README.md`` for the reading order, the CLI quickstart, and
the documented limitations of this reference. See `docs/rationale.md` and `docs/architecture.md` for
the design rationale and the architectural target.
"""
