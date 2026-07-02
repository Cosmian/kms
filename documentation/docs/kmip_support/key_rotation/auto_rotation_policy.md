# Auto-Rotation Policy

Cosmian KMS supports **scheduled, policy-driven key rotation** for SQL-backed
symmetric keys and asymmetric key pairs.  A per-key *rotation policy* is
attached to a key object; a background scheduler then rotates any key whose
interval has elapsed — without any operator action.

> **HSM keys** support manual rotation only; the auto-rotation scheduler never
> picks up HSM UIDs.  See [HSM Key Rotation](hsm.md).
>
> For the rotation flows and sequence diagrams for each key type, see
> [Key Rotation](index.md).

---

## Rotation policy attributes

All rotation-policy state is stored as vendor-extension KMIP attributes on
the key object itself:

| Attribute             | Type            | Mutable | Description                                                                          |
| --------------------- | --------------- | :-----: | ------------------------------------------------------------------------------------ |
| `x-rotate-interval`   | `i64` (seconds) | ✅      | How often to rotate.  `0` disables auto-rotation.                                   |
| `x-rotate-name`       | `string`        | ✅      | Keyset name this key belongs to (see [Key Rotation — Keysets](index.md#keysets)). |
| `x-rotate-offset`     | `i64` (seconds) | ✅      | Shift the first rotation trigger by this many seconds after `Initial Date`.          |
| `x-rotate-generation` | `i32`           | ❌      | Incremented on every rotation; `0` for never-rotated keys. **Server-managed.**       |
| `x-rotate-date`       | `datetime`      | ❌      | Timestamp of the last rotation. **Server-managed.**                                  |
| `x-rotate-latest`     | `bool`          | ❌      | `true` on the most-recent keyset member; `false` on all older keys. **Server-managed.** |

### Read-only attributes

`x-rotate-generation`, `x-rotate-date`, and `x-rotate-latest` are set
exclusively by the server during the `Re-Key` operation.  Any attempt to
modify them via `AddAttribute`, `SetAttribute`, `ModifyAttribute`, or
`DeleteAttribute` is rejected with `Attribute_Read_Only`.

These restrictions maintain two invariants relied on by the scheduler and the
keyset resolution logic:

- **Monotonic generation counter** — `x-rotate-generation` starts at `0` and
  increments by exactly `1` per rotation.  Within a keyset the generation is
  unique and strictly increasing, which lets the scheduler and client tooling
  identify the current key without inspecting every member.
- **Authoritative rotation timestamp** — `x-rotate-date` is the only reliable
  source for "when was this key last rotated".  The scheduler computes the next
  trigger as `x-rotate-date + x-rotate-interval` (previously rotated) or
  `initial_date + x-rotate-offset + x-rotate-interval` (never rotated).
  External modifications to `x-rotate-date` would cause missed or premature
  rotations.

---

## Assigning a rotation policy

Use `ckms sym keys set-rotation-policy` (or `SetAttribute` for key pairs) to
configure the mutable attributes on an existing key:

```bash
# Rotate every hour; first rotation is 60 seconds after Initial Date
ckms sym keys set-rotation-policy \
    --key-id  my-keyset   \
    --interval 3600       \
    --offset   60         \
    --name     my-keyset
```

`SetAttribute` initialises `x-rotate-generation = 0` and
`x-rotate-latest = true` on the key.  Every subsequent `Re-Key` increments
the generation, marks the new key as `latest`, and marks the old key as
non-latest.

For **asymmetric key pairs**, use `SetAttribute` directly:

```bash
ckms objects set-attribute \
    --id <PRIVATE_KEY_UID> \
    x-rotate-interval 86400
```

---

## Server configuration

### Enable the scheduler

The background scheduler is **disabled by default**.  Enable it in `kms.toml`
or via the command-line flag:

```toml
# kms.toml
auto_rotation_check_interval_secs = 300   # check every 5 minutes
```

```bash
# Command-line equivalent
cosmian_kms --auto-rotation-check-interval-secs 300
```

Set the interval to a value **smaller than the shortest `x-rotate-interval`**
on any key — otherwise some rotations will be delayed by up to one scheduler
period.

### HSM backend + KEK

The scheduler works with any database backend.  If the server is started with
a `--key-encryption-key`, KEK-wrapped keys are rotated the same as plain keys
(the server unwraps in memory, generates fresh material, re-wraps):

```bash
cosmian_kms \
  --database-type sqlite \
  --hsm-model softhsm2 \
  --hsm-slot 0 \
  --hsm-password 12345678 \
  --key-encryption-key "hsm::softhsm2::0::my-kek" \
  --auto-rotation-check-interval-secs 300
```

---

## How the scheduler works

On each tick, the scheduler:

1. Queries all **Active** symmetric keys and private keys whose
   `x-rotate-interval > 0`.
2. For each candidate, computes the next rotation deadline:
   - **Previously rotated key:** `x-rotate-date + x-rotate-interval`
   - **Never-rotated key with Initial Date:** `initial_date + x-rotate-offset + x-rotate-interval`
3. Rotates every key whose deadline is in the past.
4. Emits an OpenTelemetry counter `kms.key.auto_rotation` labelled with `uid`
   and `algorithm` for each successful rotation.

The scheduler **never returns HSM UIDs** — auto-rotation is SQL-only.

### Attribute changes on auto-rotation

| Attribute                     | Old key                              | New key                             |
| ----------------------------- | ------------------------------------ | ----------------------------------- |
| `Unique Identifier`           | unchanged                            | fresh UUID (or `name@N` for keysets) |
| `State`                       | **Deactivated** (§4.57)              | Active                              |
| `Link[ReplacementObjectLink]` | → new key UID                        | —                                   |
| `Link[ReplacedObjectLink]`    | —                                    | → old key UID                       |
| `x-rotate-generation`         | unchanged                            | old value + 1                       |
| `x-rotate-date`               | unchanged                            | timestamp of rotation               |
| `x-rotate-interval`           | **set to `0`** (cron skips old key)  | **inherited** from old key          |
| `x-rotate-name`               | unchanged                            | inherited from old key              |
| `x-rotate-offset`             | unchanged                            | inherited from old key              |
| `x-initial-date`              | cleared                              | set to now (resets next deadline)   |
| `Cryptographic Algorithm`     | unchanged                            | copied from old key                 |
| `Cryptographic Length`        | unchanged                            | copied from old key                 |

> **Note:** `x-rotate-interval` is inherited on auto-rotation (policy
> continues on the new key automatically).  On **manual** `Re-Key` it is set
> to `0` on the new key — the operator must re-arm the policy explicitly.

---

## End-to-end setup

### Step 1 — Create a key in a keyset

```bash
# SQL key: UID must equal the keyset name
ckms sym keys create --key-id my-keyset --algorithm aes --length 256
```

### Step 2 — Attach a rotation policy

```bash
ckms sym keys set-rotation-policy \
    --key-id   my-keyset \
    --name     my-keyset \
    --interval 3600      \
    --offset   60
```

### Step 3 — Enable the server scheduler

In `kms.toml`:

```toml
auto_rotation_check_interval_secs = 300
```

The scheduler will rotate `my-keyset` for the first time roughly `60 + 3600`
seconds after its `Initial Date`, and every `3600` seconds thereafter.

---

## Disabling auto-rotation on a key

Set `x-rotate-interval` to `0`:

```bash
ckms sym keys set-rotation-policy --key-id my-keyset --interval 0
```

This prevents the scheduler from selecting the key without removing any other
keyset metadata.

---

## Keyset chain depth warning

When a `Decrypt` or `Verify` call resolves a keyset name (e.g. `my-keyset`)
rather than an explicit key UID, the server walks the generation chain
newest-to-oldest until one generation succeeds.  A very deep chain indicates
that many ciphertexts are still bound to old key generations — a signal that
client-side re-encryption may be overdue.

To surface this, configure `keyset_warn_depth` in `kms.toml`:

```toml
# Emit a server warning when decryption succeeds at chain depth >= this value.
# Default: 5.  0 disables the warning.
keyset_warn_depth = 5
```

Or via the CLI flag:

```bash
cosmian_kms --keyset-warn-depth 5
```

When the threshold is reached, the server emits a `WARN` log line:

```text
Decrypt: keyset chain depth 5 >= warn threshold 5 for uid my-keyset@0;
consider re-encrypting with the latest key
```

!!! note "Traversal is unbounded"
    The chain walk has no hard limit.  All key generations remain reachable
    (subject to KMIP state rules).  `keyset_warn_depth` is purely a
    monitoring hint — it never prevents a decryption from succeeding.

---

## Observability

The server increments the OpenTelemetry counter `kms.key.auto_rotation` with
labels `uid` and `algorithm` on every successful auto-rotation.  Use your
OTel-compatible backend (Prometheus + Grafana, Datadog, …) to:

- Alert on unexpected gaps in rotation activity.
- Audit which keys were rotated and when.
- Track rotation throughput across the fleet.

See [Monitoring](../../configuration/monitoring-setup.md) for the full OTel setup guide.
