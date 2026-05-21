"""Functional-test CLI for the A2A↔MCP bridge reference.

Stdlib argparse only — no typer/click dependency. Each demo subcommand
walks through one end-to-end scenario, prints the steps with a stable
``[OK]`` / ``[REJECTED]`` / ``[ERROR]`` envelope, and exits with a
non-zero code on any unexpected outcome — so the CLI doubles as a
smoke-test runner.

Invocations::

    python -m bridge.cli demo tier1
    python -m bridge.cli demo tier2
    python -m bridge.cli demo drift     [--tier 1|2]
    python -m bridge.cli demo replay    [--tier 1|2]
    python -m bridge.cli demo unforgeable
    python -m bridge.cli demo all       # runs every scenario above

Exit codes::

    0   every step proceeded as expected
    1   a step produced an unexpected outcome (test failure)
    2   CLI usage error
"""
from __future__ import annotations

import argparse
import sys
from typing import Callable

from bridge.core.client import InMemoryTaskStore
from bridge.core.dispatcher import (
    ApprovalRequired,
    CommandSuccess,
    Dispatcher,
)
from bridge.vault import (
    InProcessVault,
    OAuthVault,
    sign_authorization_details,
)

# Importing this package registers all task-tracker commands.
import bridge.commands  # noqa: F401


# ── Output helpers ──────────────────────────────────────────────────────────


_GREEN = "\033[32m"
_RED = "\033[31m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _step(label: str, detail: str = "") -> None:
    """Print a numbered narration line. Stable format for grep-friendliness."""
    print(f"  {_DIM}…{_RESET} {label}{(' ' + detail) if detail else ''}")


def _ok(label: str) -> None:
    print(f"  {_GREEN}[OK]{_RESET} {label}")


def _rejected(label: str, reason: str = "") -> None:
    suffix = f"  ({reason})" if reason else ""
    print(f"  {_GREEN}[REJECTED]{_RESET} {label}{suffix}")


def _fail(label: str) -> None:
    print(f"  {_RED}[FAIL]{_RESET} {label}")


def _header(name: str) -> None:
    print(f"\n{_BOLD}── {name} ─{_RESET}{'─' * (60 - len(name))}")


def _outcome_summary(name: str, ok: bool) -> None:
    flag = f"{_GREEN}PASS{_RESET}" if ok else f"{_RED}FAIL{_RESET}"
    print(f"  {flag}  {name}")


# ── Scenario primitives ─────────────────────────────────────────────────────


USER_SECRET = "demo-user-signing-secret"
MINT_SECRET = "demo-vault-mint-secret"
RAR_TYPE = "tasktracker_task_action"


def _seed_two_tasks() -> tuple[InMemoryTaskStore, str, str]:
    """Common fixture: a fresh store with two tasks, returns (store, A_id, B_id)."""
    store = InMemoryTaskStore()
    a = store.create(title="Task A (approved for deletion)")
    b = store.create(title="Task B (must survive)")
    return store, a["task_id"], b["task_id"]


def _build_vault(tier: int):
    """Construct the requested Vault implementation."""
    if tier == 1:
        return InProcessVault(secret=USER_SECRET, expected_rar_type=RAR_TYPE)
    if tier == 2:
        return OAuthVault(
            user_signing_secret=USER_SECRET,
            mint_secret=MINT_SECRET,
            expected_rar_type=RAR_TYPE,
        )
    raise ValueError(f"unknown tier: {tier}")


def _sign_and_mint(vault, command: str, args: dict, approver_id: str = "alice"):
    """Step-narrated sign-then-mint."""
    _step(f"Human reviews proposed action and signs RAR payload (approver={approver_id})")
    signed = sign_authorization_details(
        command=command, args=args, rar_type=RAR_TYPE,
        approver_id=approver_id, secret=USER_SECRET,
    )
    _step(f"Bridge presents signed payload to Vault for minting")
    minted = vault.mint(signed)
    _ok(f"Vault minted credential jti={minted.jti}")
    return minted


# ── Scenarios ───────────────────────────────────────────────────────────────


def scenario_full_flow(tier: int) -> bool:
    """Happy path: human approves a delete, bridge mints, dispatcher executes."""
    _header(f"Tier {tier} — full flow (approved delete)")
    store, task_a, task_b = _seed_two_tasks()
    vault = _build_vault(tier)
    dispatcher = Dispatcher(client=store, vault=vault)

    minted = _sign_and_mint(vault, "delete-task", {"task_id": task_a})
    _step(f"Dispatcher receives delete-task(task_id={task_a}) with the minted credential")
    outcome = dispatcher.execute("delete-task", {"task_id": task_a}, approval_token=minted.credential)

    if not isinstance(outcome, CommandSuccess):
        _fail(f"expected CommandSuccess, got {type(outcome).__name__}")
        return False
    _ok("Dispatcher executed the action and returned CommandSuccess")

    remaining = {t["task_id"] for t in store.list()}
    if task_a in remaining:
        _fail(f"task {task_a} was supposed to be deleted but is still in the store")
        return False
    if task_b not in remaining:
        _fail(f"task {task_b} was not approved for deletion but is missing")
        return False
    _ok(f"Approved task is deleted; bystander task survives")
    return True


def scenario_parameter_drift(tier: int) -> bool:
    """LLM substitutes a different task_id after the human's approval. Dispatcher refuses."""
    _header(f"Tier {tier} — parameter drift (LLM substitutes a different task_id)")
    store, task_a, task_b = _seed_two_tasks()
    vault = _build_vault(tier)
    dispatcher = Dispatcher(client=store, vault=vault)

    minted = _sign_and_mint(vault, "delete-task", {"task_id": task_a})
    _step(f"After approval, LLM (adversary) substitutes task_id={task_b}")
    outcome = dispatcher.execute("delete-task", {"task_id": task_b}, approval_token=minted.credential)

    if not isinstance(outcome, ApprovalRequired):
        _fail(f"expected ApprovalRequired, got {type(outcome).__name__}")
        return False
    _rejected("Dispatcher refused the drifted action", reason=outcome.reason or "")

    remaining = {t["task_id"] for t in store.list()}
    if task_a not in remaining or task_b not in remaining:
        _fail("a task was deleted despite the dispatcher refusing")
        return False
    _ok("Both tasks survive — drift attempt did not reach the executor")
    return True


def scenario_replay(tier: int) -> bool:
    """Same credential used twice. Second use is rejected."""
    _header(f"Tier {tier} — replay (credential reused)")
    store, task_a, _ = _seed_two_tasks()
    vault = _build_vault(tier)
    dispatcher = Dispatcher(client=store, vault=vault)

    minted = _sign_and_mint(vault, "delete-task", {"task_id": task_a})
    _step("First execution")
    first = dispatcher.execute("delete-task", {"task_id": task_a}, approval_token=minted.credential)
    if not isinstance(first, CommandSuccess):
        _fail(f"first execution expected to succeed; got {type(first).__name__}")
        return False
    _ok("First execution succeeded")

    new_task = store.create(title="replay target")
    _step(f"Attacker captures the credential and tries to delete task_id={new_task['task_id']}")
    replay = dispatcher.execute(
        "delete-task", {"task_id": new_task["task_id"]}, approval_token=minted.credential
    )
    if not isinstance(replay, ApprovalRequired):
        _fail(f"replay expected to be rejected; got {type(replay).__name__}")
        return False
    _rejected("Dispatcher refused the replay", reason=replay.reason or "")
    return True


def scenario_unforgeable_without_mint_secret() -> bool:
    """Tier 2 only: a rogue Vault can sign-and-mint its own JWT, but the
    legit dispatcher refuses to validate it because the mint secret differs.
    """
    _header("Tier 2 — unforgeable without the Vault's mint secret")
    store, task_a, _ = _seed_two_tasks()

    legit_vault = OAuthVault(
        user_signing_secret=USER_SECRET, mint_secret=MINT_SECRET, expected_rar_type=RAR_TYPE,
    )
    rogue_vault = OAuthVault(
        user_signing_secret=USER_SECRET, mint_secret="ROGUE-VAULT-SECRET", expected_rar_type=RAR_TYPE,
    )
    dispatcher = Dispatcher(client=store, vault=legit_vault)

    _step("Adversary captures the human's signed RAR payload")
    signed = sign_authorization_details(
        command="delete-task", args={"task_id": task_a}, rar_type=RAR_TYPE,
        approver_id="alice", secret=USER_SECRET,
    )
    _step("Adversary stands up a rogue Vault and mints their own JWT")
    rogue_credential = rogue_vault.mint(signed)
    _ok("Rogue mint succeeded — adversary has a structurally-valid JWT")

    _step("Adversary presents the rogue JWT to the legitimate dispatcher")
    outcome = dispatcher.execute(
        "delete-task", {"task_id": task_a}, approval_token=rogue_credential.credential
    )
    if not isinstance(outcome, ApprovalRequired):
        _fail(f"dispatcher accepted a rogue-Vault JWT — Zero Trust property broken")
        return False
    _rejected("Dispatcher refused the rogue JWT", reason=outcome.reason or "")
    if task_a not in {t["task_id"] for t in store.list()}:
        _fail("rogue JWT caused a delete")
        return False
    _ok("Task survives — Zero Trust property holds")
    return True


# ── Scenario dispatcher ─────────────────────────────────────────────────────


_SCENARIOS: dict[str, Callable[[argparse.Namespace], bool]] = {
    "tier1":       lambda a: scenario_full_flow(tier=1),
    "tier2":       lambda a: scenario_full_flow(tier=2),
    "drift":       lambda a: scenario_parameter_drift(tier=a.tier),
    "replay":      lambda a: scenario_replay(tier=a.tier),
    "unforgeable": lambda a: scenario_unforgeable_without_mint_secret(),
}


def _run_all(args: argparse.Namespace) -> bool:
    results: list[tuple[str, bool]] = []
    for tier in (1, 2):
        results.append((f"tier{tier} full flow", scenario_full_flow(tier=tier)))
        results.append((f"tier{tier} drift", scenario_parameter_drift(tier=tier)))
        results.append((f"tier{tier} replay", scenario_replay(tier=tier)))
    results.append(("tier2 unforgeable", scenario_unforgeable_without_mint_secret()))

    _header("Summary")
    for name, ok in results:
        _outcome_summary(name, ok)
    return all(ok for _, ok in results)


# ── argparse ────────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bridge",
        description="A2A↔MCP bridge reference: functional smoke-test CLI.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    demo = sub.add_parser("demo", help="run a HITL-flow scenario end-to-end")
    demo_sub = demo.add_subparsers(dest="scenario", required=True)

    for name in ("tier1", "tier2"):
        demo_sub.add_parser(name, help=f"full happy-path flow on {name}")

    for name in ("drift", "replay"):
        p = demo_sub.add_parser(name, help=f"{name} scenario")
        p.add_argument("--tier", type=int, choices=(1, 2), default=1,
                       help="which Vault tier to exercise (default: 1)")

    demo_sub.add_parser("unforgeable",
                        help="Tier-2 only: rogue Vault cannot produce a credential the legit dispatcher accepts")
    demo_sub.add_parser("all", help="run every scenario and summarise")

    walk = sub.add_parser(
        "walkthrough",
        help="step-by-step simulation of the wiki sequence diagram",
    )
    walk.add_argument("--tier", type=int, choices=(1, 2), default=2,
                      help="which Vault tier to walk through (default: 2)")
    walk.add_argument("--pause", action="store_true",
                      help="wait for Enter between steps (useful for live demos)")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.cmd == "walkthrough":
        from bridge.walkthrough import walkthrough_a2a
        return walkthrough_a2a(tier=args.tier, pause=args.pause)

    if args.cmd != "demo":
        return 2

    if args.scenario == "all":
        return 0 if _run_all(args) else 1

    runner = _SCENARIOS.get(args.scenario)
    if runner is None:
        print(f"unknown scenario: {args.scenario}", file=sys.stderr)
        return 2

    return 0 if runner(args) else 1


if __name__ == "__main__":
    raise SystemExit(main())
