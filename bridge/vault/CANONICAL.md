# Canonical Authorization-Details Form

The HMAC signature that authorises a Vault to mint a credential is computed over a *canonical byte string* derived from the structured authorization-details payload. For a signer's signature to verify, the bytes the signer produced must be byte-identical to the bytes the verifier produces.

This document is the **contract** for cross-language signer implementations (an MCP host written in JavaScript, a WebAuthn relying-party in Rust, etc.). A signer that conforms to this spec produces canonical bytes that the reference Python verifier will accept.

## The canonical form

A payload is a JSON object with exactly five top-level keys:

| Key            | Type   | Description                                       |
| -------------- | ------ | ------------------------------------------------- |
| `cmd`          | string | Canonical command name (e.g. `"delete-task"`)     |
| `args`         | object | Exact arguments the human approved                |
| `rar_type`     | string | The RAR `authorization_details.type` string       |
| `exp`          | int    | POSIX seconds; payload expires when `now > exp`   |
| `approver_id`  | string | Opaque approver identity (used in audit)          |

Canonical bytes are produced by:

```python
canonical_bytes = json.dumps(
    {"cmd": cmd, "args": args, "rar_type": rar_type, "exp": exp, "approver_id": approver_id},
    sort_keys=True,          # recursive — sorts keys at every nesting level
    separators=(",", ":"),   # no whitespace anywhere
    # ensure_ascii is True by default — see "Non-ASCII strings" below
).encode("utf-8")
```

In other languages, produce bytes equivalent to a JSON encoder that:

1. **Sorts object keys** at every nesting level (lexicographic, by Unicode code point).
2. **Emits no whitespace** between tokens (`{"a":1,"b":2}`, not `{"a": 1, "b": 2}`).
3. **Encodes as UTF-8**.
4. **Escapes every non-ASCII character as `\uXXXX`** (UTF-16 surrogate pairs for code points outside the BMP). This matches Python's `json.dumps(ensure_ascii=True)` default and is REQUIRED for byte-stability across language implementations. JavaScript's `JSON.stringify` does *not* do this by default — a JS signer MUST post-process the output to escape every non-ASCII code point before HMAC computation, or use a JSON library configured to emit ASCII-only output.

## Type constraints (load-bearing)

These are the cross-language stability rules:

### `cmd`, `rar_type`, `approver_id` — strings

- Must be UTF-8.
- **Signers SHOULD apply Unicode NFC normalisation** before signing. If a signer emits `é` (é, precomposed) and a verifier expects `é` (é, decomposed), the signatures will differ. The reference does not normalise on either side; it relies on the signer to produce canonical Unicode.
- Strings MUST NOT contain control characters (U+0000 through U+001F) unless escaped per RFC 8259. The reference's Python `json.dumps` escapes them automatically.

#### Non-ASCII strings (load-bearing for cross-language signers)

Python's `json.dumps` defaults to `ensure_ascii=True`, which emits non-ASCII characters as `\uXXXX` escape sequences in the JSON output. The reference uses this default. **A non-Python signer producing canonical bytes MUST do the same.**

Example with `approver_id = "alïce@example.com"` (note the `ï`, U+00EF):

- Python (canonical, reference behaviour): emits `alïce@example.com` — the ASCII-escape form.
- JavaScript `JSON.stringify` (NON-canonical by default): emits the raw `ï` as UTF-8 bytes `0xc3 0xaf`.

These produce *different* byte strings, *different* HMACs, and the verifier will reject the JS-signed token as `SignatureMismatch`. JavaScript signers either need to use a JSON library with an `ensure_ascii`/`ascii_only` option, or post-process the JSON output to escape every code point > U+007F. Surrogate pairs for code points above U+FFFF must be emitted as two `\uXXXX` escapes per RFC 8259.

Fixture `test_fixture_6_nonascii_approver_id` in `tests/unit/test_canonical_fixtures.py` locks down the byte-exact canonical output for this case so cross-language implementations have a concrete target.

### `args` — object

- Keys: strings only. No numeric keys, no booleans-as-keys. Sorted lexicographically by Unicode code point at every nesting level.
- Values: any JSON value (string, number, boolean, null, object, array).
- **Lists are order-sensitive.** A human signing `{"tags":["a","b"]}` does NOT approve `{"tags":["b","a"]}`. Signers MUST NOT reorder list elements between display-to-human and signing.
- **Numbers**: integers as JSON integers (no decimal point). Floats as JSON numbers; floats are discouraged in `args` because cross-language float repr differs. If a value is naturally fractional, encode it as a string or a fixed-precision int (cents instead of dollars).
- **Booleans / null**: encoded as `true` / `false` / `null` (no quotes).

### `exp` — integer

- Seconds since 1970-01-01 UTC, no leap seconds (POSIX time).
- **Must be a JSON integer**, never a float. The reference's `sign_authorization_details` truncates `time.time()` to int specifically to avoid cross-language float-repr drift.
- Recommended TTL: 300 seconds (5 minutes).
- The reference Vault enforces an upper bound on the signer's requested TTL at mint time via the `max_signed_payload_ttl_seconds` constructor parameter (default 600s). A signed payload with `exp` further in the future than that bound is rejected at `mint` with `PayloadDriftAtMint`. Signers SHOULD set `exp` to `now + 300`; values much larger will be refused.

## Signature

HMAC-SHA256 over the canonical bytes, encoded as lowercase hexadecimal:

```
signature = hmac_sha256(user_signing_key, canonical_bytes).hex()
```

The hex string is 64 characters. Signers comparing signatures MUST use a constant-time comparison (e.g. `hmac.compare_digest` in Python, `crypto.timingSafeEqual` in Node, `subtle.ConstantTimeCompare` in Go).

## Worked example

Signer input:

```python
command = "delete-task"
args = {"task_id": "t-42"}
rar_type = "tasktracker_task_action"
exp = 1779315522
approver_id = "alice@example.com"
```

Canonical bytes (Python):

```python
canonical_authorization_bytes("delete-task", {"task_id": "t-42"},
                              "tasktracker_task_action", 1779315522, "alice@example.com")
# b'{"approver_id":"alice@example.com","args":{"task_id":"t-42"},"cmd":"delete-task","exp":1779315522,"rar_type":"tasktracker_task_action"}'
```

Note: top-level keys are emitted alphabetically (`approver_id` < `args` < `cmd` < `exp` < `rar_type`).

With `user_signing_key = "demo-user-signing-secret"` (this is a fixture value used to pin the canonical output for cross-language signer verification — NEVER use this string as a real deployment secret):

```python
import hmac, hashlib
canonical = b'{"approver_id":"alice@example.com","args":{"task_id":"t-42"},"cmd":"delete-task","exp":1779315522,"rar_type":"tasktracker_task_action"}'
sig = hmac.new(b"demo-user-signing-secret", canonical, hashlib.sha256).hexdigest()
# 'e48f9b6667df5269adeb35cfd09459ebfd424eb5b48a0ddd3ed911b9198988a1'
```

This fixture is encoded in `tests/unit/test_canonical_fixtures.py` and the test suite verifies the Python implementation produces these exact bytes and signature.

## What the reference does NOT enforce

The reference's Python implementation will produce bytes consistent with this spec when the *inputs* conform. It will not, on its own:

- Reject non-NFC strings (Unicode normalisation is the signer's responsibility)
- Reject float values in `args` (cross-language float repr is the signer's responsibility)
- Reject control characters in strings (Python's JSON encoder will escape them; the spec is what matters)
- Validate the `approver_id` format

A production deployment that wants stricter input validation should add a pre-canonicalisation guard that rejects non-conformant inputs before signing or before verifying. The reference does not include that guard because (a) it would complicate the demonstration, and (b) the contract is between signer and verifier, not enforced by the Vault itself.

## Versioning

If the canonical form ever changes (new field, different sort order, etc.), the version MUST be encoded in a new top-level field (`"v": 2`) so that old signatures cannot be misinterpreted under new rules. The current form is implicitly version 1. The reference does not currently emit a `v` field; a future-incompatible change would add one.
