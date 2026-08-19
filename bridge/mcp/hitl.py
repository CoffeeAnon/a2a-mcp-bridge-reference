"""Single-agent HITL gate for the MCP surface.

This is the single-agent (no-A2A) analogue of ``bridge.translation.a2a_mcp``.
Where that module translates an A2A ``auth_required`` event into an MCP
elicitation for a remote agent's action, this gate lets a *single* MCP
agent close the same secure-approval loop with no A2A at all: on an
``ApprovalRequired`` dispatch outcome it emits a URL-mode elicitation
pointing at the independent consent surface, and on a retried tool call it
resumes - reading the human's signed payload from the consent surface,
minting a credential at the Vault, and handing back the approval token the
dispatcher needs to execute.

The security core is unchanged: the human signs the exact ``(command,
args)``, the Vault mints a single-use credential bound to those bytes, and
the resource server refuses anything else. A2A is one carrier of that
signed approval between processes; this gate is the carrier for the
single-agent case, where the only hop is MCP-host -> consent surface ->
back.

**Resume correlation.** With no A2A ``context_id`` to key on, the consent
session id is derived deterministically from ``(caller, command, args)``
(``consent_session_id``). A retried ``tools/call`` recomputes the same id
and finds its own pending consent - no client-side echo required. The
merged ``SignatureReplay`` guard at the Vault prevents a retry from
double-minting.
"""
from __future__ import annotations

import hashlib
import json

from mcp import types as mcp_types

from bridge.consent.url_mode import ConsentStore
from bridge.vault import SignedAuthorizationDetails, Vault


def consent_session_id(*, caller_id: str, command: str, args: dict) -> str:
    """Deterministic, URL-safe consent-session id for one (caller, action).

    The same caller proposing the same command with the same args always
    yields the same id, so a retried tool call self-correlates to the
    pending consent. Different args (or a different caller) yield a
    different id.
    """
    canonical = json.dumps(
        {"caller": caller_id, "command": command, "args": args},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return "mcp-" + hashlib.sha256(canonical).hexdigest()[:24]


class McpHitlGate:
    """Emit a URL-mode elicitation for a HITL-gated action, and resume it.

    Construct with the shared ``ConsentStore`` (also wired into the consent
    server) and the bridge base URL. ``vault`` is required only for
    ``try_resume`` (minting the credential after approval); ``begin`` works
    without it.
    """

    def __init__(
        self,
        *,
        consent_store: ConsentStore,
        bridge_base_url: str,
        rar_type: str,
        vault: Vault | None = None,
    ) -> None:
        self._store = consent_store
        self._base_url = bridge_base_url.rstrip("/")
        self._rar_type = rar_type
        self._vault = vault
        # Credentials already minted, keyed by consent-session id, so a
        # retry after a successful mint returns the same token instead of
        # re-presenting the signed payload (which SignatureReplay rejects).
        self._minted: dict[str, str] = {}

    def begin(
        self,
        *,
        command: str,
        args: dict,
        caller_id: str,
        binding_message: str,
    ) -> mcp_types.ElicitRequestURLParams:
        """Create (idempotently) the pending consent session and return the
        URL-mode elicitation the MCP host should open."""
        sid = consent_session_id(caller_id=caller_id, command=command, args=args)
        self._store.create(
            command=command,
            args=args,
            rar_type=self._rar_type,
            approver_id=caller_id,
            binding_message=binding_message,
            session_id=sid,
        )
        return mcp_types.ElicitRequestURLParams(
            mode="url",
            message=binding_message,
            url=f"{self._base_url}/consent/{sid}",
            elicitation_id=sid,
        )

    def try_resume(
        self,
        *,
        command: str,
        args: dict,
        caller_id: str,
    ) -> str | None:
        """If the human has approved this exact action at the consent
        surface, mint a credential and return the approval token the
        dispatcher needs. Return ``None`` if approval is still pending."""
        sid = consent_session_id(caller_id=caller_id, command=command, args=args)
        if sid in self._minted:
            return self._minted[sid]
        req = self._store.get(sid)
        if req is None or req.signed_payload is None:
            return None
        if self._vault is None:
            raise ValueError("McpHitlGate.try_resume requires a vault to mint")
        signed = SignedAuthorizationDetails(
            command=req.signed_payload["command"],
            args=req.signed_payload["args"],
            rar_type=req.signed_payload["rar_type"],
            exp=req.signed_payload["exp"],
            approver_id=req.signed_payload["approver_id"],
            binding_message=req.signed_payload["binding_message"],
            signature=req.signed_payload["signature"],
        )
        minted = self._vault.mint(signed)
        self._minted[sid] = minted.credential
        return minted.credential
