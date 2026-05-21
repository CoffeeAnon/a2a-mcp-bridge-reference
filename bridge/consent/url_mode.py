"""URL-mode elicitation consent surface.

The MCP specification 2025-11-25 introduced two elicitation modes — ``form``
for structured-data collection and ``url`` for out-of-band interactions
that must not pass through the MCP client. The spec REQUIRES URL mode for
any interaction involving sensitive credentials (OAuth authorization,
payment processing, key material). Our consent step is an OAuth-style
authorization flow, so it MUST use URL mode.

This module provides the bridge's URL-mode elicitation surface as a
minimal Starlette mount with three endpoints:

  GET  /consent/<session_id>           — render the HTML consent page
                                         with the proposed authorization_details
  POST /consent/<session_id>/submit    — accept the signed payload from
                                         the page's Approve handler
  GET  /consent/<session_id>/result    — poll endpoint for the bridge's
                                         elicitation handler; returns
                                         404 until approved, then the
                                         signed payload

This is a *reference* — it intentionally has no styling, no auth, no
durable session store. A production deployment would add user
authentication on the consent page, a session store backed by Redis
or sqlite, CSRF protection on the POST, and a real signing flow
(probably WebAuthn / Passkeys to remove the HMAC-secret dependence).
The shape of the flow is what's load-bearing for the reference.

**Demo-mode key-residence warning.** The reference's ``build_consent_app``
takes a ``user_signing_secret`` and passes it to ``demo_sign_as_user`` —
a server-side stand-in for what a real client-side WebAuthn assertion
or passkey would do. This means **in the reference, the bridge process
holds the user signing key**. A bridge compromise in this configuration
is equivalent to a human-key compromise: the attacker can fabricate
signed authorization-details for any action without any human involvement.
This is acceptable for a self-contained demo (the demo must run without
a separate user-key custodian), but it is *not* the threat model the
wiki commits Tier 2 to. In production, ``user_signing_secret`` must
live on the human's MCP host (or on a hardware-backed key store the
human controls), and the bridge must NEVER hold it. The
``bridge.consent.demo_signer`` module is the seam to replace.
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from bridge.consent.demo_signer import demo_sign_as_user


@dataclass
class ConsentRequest:
    """In-memory consent-request record. One per pending elicitation."""
    session_id: str
    command: str
    args: dict
    rar_type: str
    approver_id: str
    binding_message: str
    created_at: float = field(default_factory=time.time)
    signed_payload: Optional[dict] = None  # populated on successful submit
    denied: bool = False


class ConsentStore:
    """Thread-safe in-memory store. Single-process only.

    Production deployments should swap this for a Redis-backed store with
    TTL eviction so the consent page can survive bridge restarts.
    """

    def __init__(self) -> None:
        self._requests: dict[str, ConsentRequest] = {}
        self._lock = threading.Lock()

    def create(
        self,
        *,
        command: str,
        args: dict,
        rar_type: str,
        approver_id: str,
        binding_message: str,
    ) -> ConsentRequest:
        session_id = secrets.token_urlsafe(16)
        req = ConsentRequest(
            session_id=session_id,
            command=command,
            args=args,
            rar_type=rar_type,
            approver_id=approver_id,
            binding_message=binding_message,
        )
        with self._lock:
            self._requests[session_id] = req
        return req

    def get(self, session_id: str) -> Optional[ConsentRequest]:
        with self._lock:
            return self._requests.get(session_id)

    def submit_signed(self, session_id: str, signed_payload: dict) -> bool:
        with self._lock:
            req = self._requests.get(session_id)
            if req is None or req.signed_payload is not None or req.denied:
                return False
            req.signed_payload = signed_payload
            return True

    def deny(self, session_id: str) -> bool:
        with self._lock:
            req = self._requests.get(session_id)
            if req is None or req.signed_payload is not None or req.denied:
                return False
            req.denied = True
            return True


_CONSENT_PAGE_TEMPLATE = """<!DOCTYPE html>
<html><head><title>Approve action</title>
<style>body{{font-family:sans-serif;max-width:600px;margin:2em auto;}}
.action{{background:#fff7d6;padding:1em;border-left:4px solid #d8a800;}}
.params{{font-family:monospace;background:#f5f5f5;padding:1em;white-space:pre-wrap;}}
.btn{{padding:0.6em 1.2em;margin:0.5em 0.5em 0 0;cursor:pointer;}}
.approve{{background:#1d6b1d;color:white;border:none;}}
.deny{{background:#aa1d1d;color:white;border:none;}}</style></head>
<body>
<h2>Approve agent action</h2>
<div class="action">
  <p><strong>{binding_message}</strong></p>
  <p>The agent is requesting permission to perform:</p>
  <div class="params">
command: {command}
args:    {args_pretty}
type:    {rar_type}
  </div>
  <p>Approving this credential authorises <em>this exact action with these
  exact arguments</em>, single-use, valid for 5 minutes. Any other action —
  or this action with different arguments — will require separate approval.</p>
</div>
<form method="POST" action="/consent/{session_id}/submit">
  <button class="btn approve" type="submit" name="decision" value="approve">Approve</button>
  <button class="btn deny" type="submit" name="decision" value="deny">Deny</button>
</form>
</body></html>
"""


def render_consent_page(req: ConsentRequest) -> str:
    return _CONSENT_PAGE_TEMPLATE.format(
        binding_message=req.binding_message,
        command=req.command,
        args_pretty=json.dumps(req.args, indent=2),
        rar_type=req.rar_type,
        session_id=req.session_id,
    )


def build_consent_app(
    *,
    store: ConsentStore,
    user_signing_secret: str,
) -> Starlette:
    """Build a Starlette sub-app exposing the consent endpoints.

    ``user_signing_secret`` is the secret the user-side signing function
    uses. In a real deployment the user would hold this key; in the
    reference it's shared with the Vault for simplicity.
    """

    async def _render(request) -> Response:
        session_id = request.path_params["session_id"]
        req = store.get(session_id)
        if req is None:
            return HTMLResponse("<h3>Unknown consent session</h3>", status_code=404)
        if req.signed_payload is not None:
            return HTMLResponse("<h3>Already approved.</h3>")
        if req.denied:
            return HTMLResponse("<h3>Denied.</h3>")
        return HTMLResponse(render_consent_page(req))

    async def _submit(request) -> Response:
        session_id = request.path_params["session_id"]
        req = store.get(session_id)
        if req is None:
            return HTMLResponse("<h3>Unknown consent session</h3>", status_code=404)

        form = await request.form()
        decision = form.get("decision", "")

        if decision == "deny":
            store.deny(session_id)
            return HTMLResponse("<h3>Denied.</h3>")

        if decision != "approve":
            return HTMLResponse("<h3>Bad decision</h3>", status_code=400)

        signed = demo_sign_as_user(
            command=req.command,
            args=req.args,
            rar_type=req.rar_type,
            approver_id=req.approver_id,
            user_secret=user_signing_secret,
        )
        store.submit_signed(session_id, signed)
        return HTMLResponse("<h3>Approved. You may close this window.</h3>")

    async def _result(request) -> Response:
        session_id = request.path_params["session_id"]
        req = store.get(session_id)
        if req is None:
            return JSONResponse({"error": "unknown session"}, status_code=404)
        if req.denied:
            return JSONResponse({"status": "denied"}, status_code=200)
        if req.signed_payload is None:
            return JSONResponse({"status": "pending"}, status_code=202)
        return JSONResponse({"status": "approved", "signed": req.signed_payload})

    return Starlette(routes=[
        Route("/consent/{session_id}", _render, methods=["GET"]),
        Route("/consent/{session_id}/submit", _submit, methods=["POST"]),
        Route("/consent/{session_id}/result", _result, methods=["GET"]),
    ])
