"""URL-mode elicitation consent server.

The MCP specification 2025-11-25 requires URL mode for sensitive
consent (OAuth, payment, key material). This package implements the
bridge-hosted consent surface the URL points at:

  - ``url_mode.py``    — Starlette mount with three endpoints:
                        GET  /consent/<session>           render page
                        POST /consent/<session>/submit    user approves/denies
                        GET  /consent/<session>/result    bridge polls for signed payload
  - ``demo_signer.py`` — DEMO-ONLY stand-in for client-side signing.
                        A production deployment moves this to the
                        human's MCP host (WebAuthn / Passkey) and
                        the bridge process NEVER holds the user
                        signing key. The function lives in its own
                        module so it's visibly the seam to replace.

Requires the ``[mcp]`` extras (Starlette + python-multipart).
"""
