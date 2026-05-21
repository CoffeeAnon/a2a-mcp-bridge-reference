"""Cross-language stability fixtures for the canonical authorization-details form.

Locks down the byte-level output of ``canonical_authorization_bytes`` and
the HMAC signature for a set of known inputs. If the Python implementation
ever drifts from these fixtures, the test fails immediately — preventing
silent divergence from the spec at ``bridge/vault/CANONICAL.md``.

These fixtures are the contract a non-Python signer must match. A JS or
Rust signer that produces the same canonical bytes for the same inputs
will produce the same signature, and the Python verifier will accept it.

If you intentionally change the canonical form, update both this file
and ``CANONICAL.md`` in the same commit and bump the version field.
"""
import hashlib
import hmac

from bridge.vault.in_process import (
    canonical_authorization_bytes,
    sign_authorization_details,
)


USER_SECRET = "demo-user-signing-secret"


# ── Fixture set 1: the minimal delete-task case ─────────────────────────────


_FIX_1_INPUT = dict(
    command="delete-task",
    args={"task_id": "t-42"},
    rar_type="tasktracker_task_action",
    exp=1779315522,
    approver_id="alice@example.com",
)
_FIX_1_CANONICAL = (
    b'{"approver_id":"alice@example.com",'
    b'"args":{"task_id":"t-42"},'
    b'"cmd":"delete-task",'
    b'"exp":1779315522,'
    b'"rar_type":"tasktracker_task_action"}'
)


def test_fixture_1_canonical_bytes():
    actual = canonical_authorization_bytes(**_FIX_1_INPUT)
    assert actual == _FIX_1_CANONICAL


def test_fixture_1_signature():
    sig = hmac.new(USER_SECRET.encode(), _FIX_1_CANONICAL, hashlib.sha256).hexdigest()
    # The signature value below is locked in. If this changes, the canonical
    # form has changed and CANONICAL.md must be updated.
    assert sig == "e48f9b6667df5269adeb35cfd09459ebfd424eb5b48a0ddd3ed911b9198988a1"


# ── Fixture set 2: nested dict in args (recursive sort_keys) ────────────────


_FIX_2_INPUT = dict(
    command="update-resource",
    # Deliberately constructed with unsorted keys at every nesting level.
    args={
        "resource_id": "r-1",
        "patch": {"z_last": 1, "a_first": 2, "m_middle": 3},
    },
    rar_type="resource_action",
    exp=1779315522,
    approver_id="bob@example.com",
)
_FIX_2_CANONICAL = (
    b'{"approver_id":"bob@example.com",'
    b'"args":{"patch":{"a_first":2,"m_middle":3,"z_last":1},"resource_id":"r-1"},'
    b'"cmd":"update-resource",'
    b'"exp":1779315522,'
    b'"rar_type":"resource_action"}'
)


def test_fixture_2_recursive_key_sort():
    """Nested dicts must have their keys sorted at every level."""
    actual = canonical_authorization_bytes(**_FIX_2_INPUT)
    assert actual == _FIX_2_CANONICAL


# ── Fixture set 3: list values preserve order ──────────────────────────────


_FIX_3_INPUT_AB = dict(
    command="tag-resource",
    args={"id": "r-1", "tags": ["a", "b"]},
    rar_type="tag_action",
    exp=1779315522,
    approver_id="carol@example.com",
)
_FIX_3_INPUT_BA = dict(
    command="tag-resource",
    args={"id": "r-1", "tags": ["b", "a"]},
    rar_type="tag_action",
    exp=1779315522,
    approver_id="carol@example.com",
)


def test_fixture_3_list_order_is_significant():
    """The canonical form preserves list order; ["a","b"] != ["b","a"]."""
    ab = canonical_authorization_bytes(**_FIX_3_INPUT_AB)
    ba = canonical_authorization_bytes(**_FIX_3_INPUT_BA)
    assert ab != ba, "list order MUST be significant"


# ── Fixture set 4: sign_authorization_details produces int exp ─────────────


def test_sign_helper_produces_int_exp():
    """Defends against future regressions back to float exp."""
    signed = sign_authorization_details(
        command="delete-task",
        args={"task_id": "t-42"},
        rar_type="tasktracker_task_action",
        approver_id="alice@example.com",
        secret=USER_SECRET,
    )
    assert isinstance(signed.exp, int), "exp must be int for cross-language stability"


# ── Fixture set 5: same inputs → identical bytes across calls ──────────────


def test_canonical_is_deterministic():
    """Two calls with the same inputs produce byte-identical output."""
    a = canonical_authorization_bytes(**_FIX_1_INPUT)
    b = canonical_authorization_bytes(**_FIX_1_INPUT)
    assert a == b


# ── Negative fixture: drifted args produce different canonical bytes ──────


def test_arg_drift_changes_canonical_bytes():
    base = canonical_authorization_bytes(**_FIX_1_INPUT)
    drifted_input = {**_FIX_1_INPUT, "args": {"task_id": "t-43"}}
    drifted = canonical_authorization_bytes(**drifted_input)
    assert base != drifted
