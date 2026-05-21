"""A2A `auth_required` ↔ MCP elicitation translation.

The two protocols carry the same *information* through different
envelopes; the bridge's job is to move that information across without
losing the parameter-binding property and without inventing new trust
claims of its own.

Translation direction 1: **A2A → MCP** (agent paused, ask the human)

    A2A emits ``task_status_update`` with ``state="auth_required"`` and a
    DataPart carrying ``authorization_details`` + a binding message. The
    bridge translates this into an MCP ``elicitation/create`` request
    (URL-mode per the 2025-11-25 spec, because the consent step involves
    OAuth-style sensitive interaction). The MCP host renders the URL,
    the user reviews the proposed action, and approves with a signature
    over the same canonical authorization-details payload.

Translation direction 2: **MCP → A2A** (human approved, resume the agent)

    MCP elicitation response contains the human's signed RAR payload.
    The bridge translates this into an A2A ``message:send`` with a
    DataPart carrying ``{approved: true, payload, signature}`` for the
    same ``context_id`` the task was paused under.

What this module does NOT do: actually transport messages over A2A or
MCP. It produces and consumes the *payload shapes* both protocols use,
making the translation testable without a network. A production bridge
wires these shapes into a2a-sdk and the mcp Python SDK; the translation
logic stays here.

The translation preserves three properties:

  1. ``context_id`` continuity. The MCP elicitation carries an
     ``elicitation_id`` derived from the A2A context, so the resume
     message can be routed back to the paused task.
  2. ``authorization_details`` is forwarded byte-identical. The bridge
     does NOT re-canonicalise, does NOT reorder keys, does NOT alter
     anything. What the agent proposed is exactly what the human signs.
  3. URL-mode elicitation is enforced. Sensitive OAuth-style consent
     MUST NOT pass through the MCP client's form-mode handler per the
     spec.

The ``elicitation_id`` shape (``el:<context_id>:<task_id>``) is
**bridge-internal**: the signer never sees it, the Vault never
validates it, and a multi-replica bridge deployment that needs cross-
replica elicitation routing would need to choose a different shape
(e.g., a signed token, or a Redis-backed mapping). Not part of the
spec at ``bridge/vault/CANONICAL.md``; the canonical-form contract
covers only what the *signer* sees.
"""
from __future__ import annotations

from dataclasses import dataclass


class TranslationError(ValueError):
    """Raised when a translation input violates a structural precondition.

    Distinct from Vault/RS errors: this is about *message shape*, not
    authorization decisions. The bridge translates only well-formed
    payloads; a malformed input is a programming error in the caller.
    """


# ── Protocol-shape dataclasses ─────────────────────────────────────────────


@dataclass(frozen=True)
class A2aAuthRequiredEvent:
    """A2A ``task_status_update`` event with state=auth_required.

    Shape matches the sequence diagram in `docs/architecture.md` §"A2A surface" and the A2A
    protocol spec. Constructed by the agent's executor when its dispatch
    hits a HITL-gated tool.
    """
    task_id: str
    context_id: str
    authorization_details: dict   # the RAR dict the human will approve
    binding_message: str          # human-readable summary for the elicitation prompt


@dataclass(frozen=True)
class McpElicitationRequest:
    """MCP ``elicitation/create`` request body.

    URL-mode per the 2025-11-25 spec: the MCP host renders the URL in a
    secure surface (sandboxed iframe via MCP Apps / SEP-1865, or a
    browser redirect), the user reviews the action, signs, and POSTs
    back to the bridge's consent endpoint. The MCP client returns the
    *result* of the URL-mode interaction via the elicitation response.
    """
    elicitation_id: str
    mode: str                     # "url"; see CANONICAL.md and the MCP spec
    url: str                      # bridge-hosted consent page for this elicitation_id
    title: str
    description: str              # the binding message, rendered to the user
    authorization_details: dict   # forwarded byte-identical from A2A


@dataclass(frozen=True)
class McpElicitationResponse:
    """MCP host's reply once the user has interacted with the URL.

    Carries the human's signed authorization-details payload. The
    bridge never inspects the signature itself - it forwards the
    payload to the Vault for verify-and-mint.
    """
    elicitation_id: str
    action: str                   # "accept" | "decline" | "cancel" (MCP spec values)
    signed_payload: dict | None   # present only when action == "accept"


@dataclass(frozen=True)
class A2aResumeMessage:
    """A2A ``message:send`` body resuming a paused task with the human's reply.

    Carries an ``approved: bool`` + (when approved) the human's signed
    payload as a DataPart. The agent's executor unblocks the
    ``interrupt()`` with this value.
    """
    context_id: str
    approved: bool
    signed_payload: dict | None
    rejection_reason: str | None  # populated when approved is False


# ── Translation functions ──────────────────────────────────────────────────


def a2a_auth_required_to_mcp_elicitation(
    event: A2aAuthRequiredEvent,
    *,
    bridge_base_url: str,
) -> McpElicitationRequest:
    """Translate A2A → MCP. Pattern-1 direction 1.

    The bridge mints an ``elicitation_id`` derived from the A2A context
    so the eventual MCP elicitation response can be routed back to the
    correct paused task. The URL points at the bridge's consent server
    (``bridge.consent.url_mode``), which renders the action details and
    accepts the human's signature.

    The ``authorization_details`` dict is forwarded byte-identical. The
    bridge MUST NOT re-canonicalise it: the human will sign over the same
    bytes the agent proposed, and any normalisation would break that
    property.
    """
    _require_nonempty(event.task_id, "task_id")
    _require_nonempty(event.context_id, "context_id")
    _require_nonempty(event.binding_message, "binding_message")
    if not isinstance(event.authorization_details, dict):
        raise TranslationError(
            f"authorization_details must be a dict, got {type(event.authorization_details).__name__}"
        )
    # The elicitation_id shape ``el:<context_id>:<task_id>`` uses ``:``
    # as a separator. A context_id or task_id containing ``:`` would
    # silently corrupt the round-trip parse - failure would surface later
    # as "wrong task resumed" rather than a clear error here. Reject at
    # construction time. For carriers needing arbitrary content (for
    # example, URN-shaped context_ids), see the module docstring: the
    # elicitation_id format is bridge-private and would need to change
    # to a base64url or signed-token shape.
    if ":" in event.context_id:
        raise TranslationError(
            f"context_id must not contain ':' (used as elicitation_id separator): "
            f"{event.context_id!r}"
        )
    if ":" in event.task_id:
        raise TranslationError(
            f"task_id must not contain ':' (used as elicitation_id separator): "
            f"{event.task_id!r}"
        )

    elicitation_id = f"el:{event.context_id}:{event.task_id}"
    return McpElicitationRequest(
        elicitation_id=elicitation_id,
        mode="url",
        url=f"{bridge_base_url.rstrip('/')}/consent/{elicitation_id}",
        title="Approve agent action",
        description=event.binding_message,
        authorization_details=event.authorization_details,
    )


def mcp_elicitation_response_to_a2a_resume(
    response: McpElicitationResponse,
) -> A2aResumeMessage:
    """Translate MCP → A2A. Pattern-1 direction 2.

    Maps the MCP elicitation ``action`` value to the boolean
    ``approved`` flag the agent's HITL gate expects, recovers the
    ``context_id`` from the elicitation_id, and forwards the signed
    payload unchanged.

    Per the MCP spec, ``action`` is one of:
      - ``"accept"``: human approved; ``signed_payload`` must be present
      - ``"decline"``: human refused
      - ``"cancel"``: host cancelled (timeout, UI closed); treat as decline
    """
    _require_nonempty(response.elicitation_id, "elicitation_id")
    _require_nonempty(response.action, "action")

    context_id = _context_id_from_elicitation_id(response.elicitation_id)

    if response.action == "accept":
        if response.signed_payload is None:
            raise TranslationError(
                "MCP elicitation action='accept' requires signed_payload"
            )
        return A2aResumeMessage(
            context_id=context_id,
            approved=True,
            signed_payload=response.signed_payload,
            rejection_reason=None,
        )
    if response.action in ("decline", "cancel"):
        return A2aResumeMessage(
            context_id=context_id,
            approved=False,
            signed_payload=None,
            rejection_reason=response.action,
        )
    raise TranslationError(
        f"unknown MCP elicitation action: {response.action!r} "
        "(expected one of accept|decline|cancel)"
    )


# ── Helpers ────────────────────────────────────────────────────────────────


def _require_nonempty(value: str, name: str) -> None:
    if not value:
        raise TranslationError(f"{name} must not be empty")


def _context_id_from_elicitation_id(elicitation_id: str) -> str:
    """Recover the A2A context_id from an elicitation_id minted earlier.

    ``elicitation_id`` shape: ``el:<context_id>:<task_id>``. Anything
    else is a TranslationError - these IDs are minted by us, so an
    unexpected shape means something has tampered with them en route.
    """
    parts = elicitation_id.split(":")
    if len(parts) < 3 or parts[0] != "el" or not parts[1]:
        raise TranslationError(
            f"elicitation_id does not match expected shape 'el:<context>:<task>': "
            f"{elicitation_id!r}"
        )
    return parts[1]
