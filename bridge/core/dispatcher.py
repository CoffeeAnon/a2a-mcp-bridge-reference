"""Command dispatcher with HITL gate.

Pure logic — no printing, no exit codes. Used by both the agent's in-process
invoker and any CLI wrapper that wants to call commands directly.

The HITL gate is the single load-bearing primitive: when a command's class
declares ``hitl=True``, dispatch refuses to execute without a valid
credential. Validation can happen in one of two places:

  - **Vault-backed (Tier 1 in-process):** dispatcher calls
    ``Vault.consume(credential, command, args)``. The Vault holds the
    consumed-jti state. Used when the resource server is not separated
    from the dispatcher (Tier 1 InProcessVault, or Tier 2 OAuthVault
    when the deployment co-locates them).

  - **RS-backed (Tier 2 with separated RS):** dispatcher forwards
    ``(command, args, credential)`` to ``ResourceServer.execute``, which
    does its own JWT verify + binding check + single-use enforcement
    against the RS's own state, then executes. This is the deployment
    shape the wiki's "three independent enforcement layers" claim
    requires.

A ``Dispatcher`` is constructed with exactly one of ``vault=`` or
``resource_server=``; passing neither is a programming error.
"""
from dataclasses import dataclass
from typing import Any, Union

from bridge.core.client import ApiError, BridgeClient
from bridge.core.registry import REGISTRY
from bridge.rs import JwtResourceServer, RsError, RsRejected, RsSuccess
from bridge.vault import Vault, VaultError


# ── Outcome types — the structured return from Dispatcher.execute() ──────────

@dataclass(frozen=True)
class CommandSuccess:
    items: list[dict]
    meta: dict


@dataclass(frozen=True)
class CommandError:
    status: int | str
    message: str
    context: dict | None


@dataclass(frozen=True)
class ApprovalRequired:
    """Returned when a HITL-gated command was attempted without a valid credential.

    ``reason`` is populated with the Vault exception's class name when a
    Vault-backed dispatcher refused a presented credential — e.g.
    ``"CredentialDrift"``, ``"CredentialReplay"``, ``"CredentialExpired"``,
    ``"SignatureMismatch"``. Callers should treat ``reason`` as an audit-
    attribution hint, not as part of the security contract (the contract
    is "the command did not execute"). ``reason`` is ``None`` when no
    credential was presented at all.
    """
    command: str
    args: dict
    reason: str | None = None


CommandOutcome = Union[CommandSuccess, CommandError, ApprovalRequired]


_RESERVED_META_KEYS = {"count", "status", "command"}


class Dispatcher:
    """Stateful dispatcher: holds either a Vault or a separated Resource
    Server across calls. Exactly one of ``vault`` / ``resource_server``
    must be provided.

    Constructor parameters:
      client: resource-server client used by the Vault-backed path
              (defaults to ``InMemoryTaskStore``). Ignored when a
              separated ``resource_server`` is provided — the RS holds
              its own client.
      vault:  ``Vault`` implementation. Co-located mint + consume +
              execute in one trust domain.
      resource_server: ``JwtResourceServer`` for the separated shape.
              When provided, the dispatcher forwards
              ``(command, args, credential)`` to the RS, which validates
              the JWT independently against its own state.
    """

    def __init__(
        self,
        client: Any | None = None,
        vault: Vault | None = None,
        resource_server: JwtResourceServer | None = None,
    ) -> None:
        if (vault is None) == (resource_server is None):
            raise ValueError(
                "Dispatcher requires exactly one of `vault` or `resource_server`"
            )
        self._client = client if client is not None else BridgeClient()
        self._vault = vault
        self._rs = resource_server

    def execute(
        self,
        command_name: str,
        kwargs: dict,
        approval_token: str | None = None,
    ) -> CommandOutcome:
        """Run a command and return a structured outcome."""
        cmd_cls = REGISTRY.get(command_name)
        if cmd_cls is None:
            return CommandError(
                status="unknown",
                message=f"Unknown command: {command_name}",
                context=None,
            )

        collision = _RESERVED_META_KEYS & kwargs.keys()
        if collision:
            raise RuntimeError(
                f"Command kwargs must not use reserved meta keys: {collision}"
            )

        if cmd_cls.hitl:
            if not approval_token:
                return ApprovalRequired(command=command_name, args=dict(kwargs))

            if self._rs is not None:
                return self._execute_via_rs(command_name, kwargs, approval_token)

            return self._execute_via_vault(command_name, kwargs, approval_token, cmd_cls)

        # Non-HITL path: dispatcher executes locally.
        return self._execute_locally(command_name, kwargs, cmd_cls)

    # ── HITL execution paths ────────────────────────────────────────────

    def _execute_via_vault(
        self,
        command_name: str,
        kwargs: dict,
        approval_token: str,
        cmd_cls,
    ) -> CommandOutcome:
        try:
            self._vault.consume(approval_token, command_name, kwargs)
        except VaultError as exc:
            return ApprovalRequired(
                command=command_name,
                args=dict(kwargs),
                reason=type(exc).__name__,
            )
        return self._execute_locally(command_name, kwargs, cmd_cls)

    def _execute_via_rs(
        self,
        command_name: str,
        kwargs: dict,
        approval_token: str,
    ) -> CommandOutcome:
        outcome = self._rs.execute(command_name, kwargs, approval_token)
        if isinstance(outcome, RsSuccess):
            return CommandSuccess(items=outcome.items, meta=outcome.meta)
        if isinstance(outcome, RsError):
            return CommandError(
                status=outcome.status, message=outcome.message, context=outcome.context,
            )
        if isinstance(outcome, RsRejected):
            return ApprovalRequired(
                command=command_name,
                args=dict(kwargs),
                reason=outcome.reason,
            )
        # Defensive: unknown RS outcome shape.
        return CommandError(status="rs_unknown_outcome", message=str(outcome), context=None)

    # ── Non-HITL execution ──────────────────────────────────────────────

    def _execute_locally(
        self,
        command_name: str,
        kwargs: dict,
        cmd_cls,
    ) -> CommandOutcome:
        try:
            items = cmd_cls().execute(client=self._client, **kwargs)
        except ApiError as e:
            return CommandError(status=e.status_code, message=e.body, context=dict(kwargs))
        except ValueError as e:
            return CommandError(status=400, message=str(e), context=dict(kwargs))
        meta = {**kwargs, "count": len(items), "status": "ok"}
        return CommandSuccess(items=items, meta=meta)
