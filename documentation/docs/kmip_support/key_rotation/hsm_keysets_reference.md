# HSM keysets reference

This page describes the identifiers, addressing rules, rotation schedule, attributes and errors of HSM keysets: keys resident on a PKCS#11 HSM that Eviden KMS rotates with `Re-Key`, `Re-Key Key Pair` and the auto-rotation scheduler. For step-by-step instructions see [How to rotate HSM keys](hsm_keysets_how_to.md); for the design rationale see [HSM keysets explained](hsm_keysets_explanation.md).

## Identifiers

### Unique identifiers

| Object | Unique identifier |
| --- | --- |
| Generation 0 (the original key) | `hsm::<model>::<slot_id>::<key_id>` (the **base UID**) |
| Generation N, N ≥ 1 | `hsm::<model>::<slot_id>::<key_id>@N` |
| Public key of a key pair | private key UID + `_pk`, e.g. `hsm::<model>::<slot_id>::<key_id>@N_pk` |

`<model>` is the HSM instance prefix described in [Multi-HSM support](../../hsm_support/multi_hsm.md). The older two-segment form `hsm::<slot_id>::<key_id>` is still accepted. The generation number is a signed 32-bit integer; a re-key of generation `2147483647` is rejected with an error instead of overflowing.

Examples from the server tests (two-segment form): `hsm::0::kp` is rotated to `hsm::0::kp@1`, and its public key `hsm::0::kp_pk` to `hsm::0::kp@1_pk`.

### Keyset name

The keyset name (`x-rotate-name`) of an HSM key **must be its base UID**, so a keyset never spans two slots or two HSM instances.

| `x-rotate-name` value for key `hsm::softhsm2::0::my-hsm-key` | Accepted? |
| --- | :---: |
| `hsm::softhsm2::0::my-hsm-key` | ✅ |
| `my-hsm-keyset` (bare name) | ❌ |
| `hsm::softhsm2::0::my-hsm-key@1` (generation suffix) | ❌ |

A refused name returns `Invalid_Field`:

```text
SetAttribute: for HSM keys, rotate_name must be the key's base UID ('hsm::softhsm2::0::my-hsm-key'), not 'my-hsm-keyset'
```

The public keys of a key pair form their own keyset, named `{rotate_name}_pk`, which is the base UID of the generation-0 public key.

### `CKA_LABEL` format

Keyset membership and generation are stored in `CKA_LABEL` as `{rotate_name}::{generation}::{key_id}[@latest]`, where `key_id` is the base key identifier (without `@N`). The label is parsed from the right, so the `::` separators inside `rotate_name` are harmless.

| `CKA_LABEL` | Meaning |
| --- | --- |
| `{key_id}` (or a tag envelope) | Key not in a keyset |
| `{rotate_name}::0::{key_id}@latest` | Generation 0 just after enrollment |
| `{rotate_name}::{N}::{key_id}@latest` | Keyset head after the N-th rotation |
| `{rotate_name}::{N}::{key_id}` | Retired generation |
| `{rotate_name}_pk::{N}::{key_id}_pk[@latest]` | Public key of generation N |

Labels written by the server tests after one automatic rotation of the AES key `hsm::0::k1` and of the RSA key pair `hsm::0::kp`:

| Object | `CKA_LABEL` |
| --- | --- |
| `hsm::0::k1` | `hsm::0::k1::0::k1` |
| `hsm::0::k1@1` | `hsm::0::k1::1::k1@latest` |
| `hsm::0::kp` | `hsm::0::kp::0::kp` |
| `hsm::0::kp@1` | `hsm::0::kp::1::kp@latest` |
| `hsm::0::kp_pk` | `hsm::0::kp_pk::0::kp_pk` |
| `hsm::0::kp@1_pk` | `hsm::0::kp_pk::1::kp_pk@latest` |

Tags set on the key are kept: the keyset label is stored inside the tag envelope described in [HSM key labeling & tagging](../../hsm_support/tagging.md). The whole label must fit the token's `CKA_LABEL` length limit (see the [vendor quirks table](../../hsm_support/algorithm_support.md#vendor-specific-quirks)).

The **keyset head** is the member with the highest generation. The `@latest` marker is informative; the generation number decides.

## Addressing

A request may name an HSM keyset generation in four forms. The table gives the key each operation uses.

| Address | Encrypt, Sign, MAC | Decrypt | Signature Verify, MAC Verify | Re-Key, Re-Key Key Pair |
| --- | --- | --- | --- | --- |
| `hsm::m::s::k` (bare base UID) | head | each generation, newest to oldest, until one decrypts (some modes refused, see below) | each generation, newest to oldest, until one answers `Valid` | head |
| `hsm::m::s::k@latest` | head | head only | head only | head |
| `hsm::m::s::k@first`, `hsm::m::s::k@0` | generation 0, **only if it is the head** | generation 0 | generation 0 | generation 0, **only if it is the head** |
| `hsm::m::s::k@N`, N ≥ 1 | generation N, **only if it is the head** | generation N | generation N | generation N, **only if it is the head** |

Rules that apply to the table:

- **Retired generations are `Deactivated` for protection.** A generation that is not the head is treated as `Deactivated` for cryptographic operations: Encrypt, Sign and MAC with it fail with `Wrong_Key_Lifecycle_State`, for example `Encrypt: key <uid> is in state Deactivated but operation requires one of [Active]`. Decrypt, Signature Verify and MAC Verify accept every generation.
- **Re-Key of a retired generation is refused.** A Re-Key or Re-Key Key Pair on `@N`, `@first` or `@0` that is not the head fails with `Invalid_Field`; the message contains `is not the latest in its keyset`. A Re-Key on an explicit `@N` that does not exist fails with `Item_Not_Found`: an explicitly addressed generation is never redirected to the head. The bare base UID and `@latest` always rotate the head, even when generation 0 has been destroyed.
- **Verification by a bare name walks the whole keyset.** Signature Verify and MAC Verify try every generation until one answers `Valid`; when none does, the response is `Invalid`, not an error. This applies to SQL and HSM keysets.
- **Decryption by a bare name needs a mode that detects a wrong key.** Without cryptographic parameters it uses AES-GCM or RSA-OAEP with SHA-256, never CBC or PKCS#1 v1.5; an explicit generation (`@N`, `@first`, `@0`) may use CBC or PKCS#1 v1.5. The full rule is in [Bare-name decryption and wrong-key detection](index.md#bare-name-decryption-and-wrong-key-detection).
- **Cryptographic operations run on the token.** Every operation addressed by keyset runs on the HSM. Keep keys non-extractable when their material must not leave the token: metadata retrieval can export extractable keys. On a FIPS build, AES-GCM Encrypt by keyset address fails on an HSM that cannot generate the GCM IV itself (for example SoftHSM2, Kryoptic); see [AES-GCM IVs and HSM FIPS mode](../../hsm_support/hsm_aes_gcm_iv.md).
- **Authorization applies to the selected generation.** The caller must hold the operation's grant on the generation the server selects; see [HSM key authorization model](../../hsm_support/hsm_operations.md#hsm-key-authorization-model).
- **Resolution is cached.** Keyset lookups are cached for two seconds; a rotation made on another KMS node sharing the HSM becomes visible after that delay. See [RotateNameCache](../../configuration/object-cache.md#rotatenamecache).

## Rotation schedule

The schedule lives in the PKCS#11 `CKA_START_DATE` and `CKA_END_DATE` attributes of the keyset head (of the private key for a key pair). These attributes have day granularity.

| Action | Effect on the token |
| --- | --- |
| `SetAttribute RotateInterval = n`, n ≥ 86400 | `CKA_START_DATE` = today, `CKA_END_DATE` = today + ⌈n / 86400⌉ days; then, if the key is not in a keyset yet, it is enrolled under its base UID (generation-0 label `{base UID}::0::{key_id}@latest`) |
| `SetAttribute RotateInterval = 0` | both dates cleared: auto-rotation disarmed; keyset membership (`CKA_LABEL`) is kept. A token that refuses to unset a date (Proteccio) gets `CKA_START_DATE` = `CKA_END_DATE` = today instead: a validity shorter than one day is never a schedule |
| `SetAttribute RotateInterval = n`, 0 < n < 86400 | refused, `Invalid_Field` |
| Re-Key (manual or automatic) of a key with dates | new key: `CKA_START_DATE` = rotation day, `CKA_END_DATE` = rotation day + the old interval |

### Due rule

The scheduler rotates an HSM key when **all** of the following hold:

1. the key is in a keyset: its `CKA_LABEL` carries the keyset label `{rotate_name}::{generation}::{key_id}`;
2. both `CKA_START_DATE` and `CKA_END_DATE` are set;
3. `CKA_END_DATE` − `CKA_START_DATE` ≥ 1 day;
4. today (UTC) ≥ `CKA_END_DATE`;
5. the key is the keyset head.

A key whose dates were set by another PKCS#11 application is never rotated, whether it has only `CKA_END_DATE` or both dates, as long as it carries no keyset label. A retired generation keeps its past `CKA_END_DATE` but is never rotated again, so a repeated tick does not rotate twice.

Setting a positive `RotateInterval` through the KMS enrolls the key, so a key armed with `set-rotation-policy --interval` always meets condition 1. A manual Re-Key of a key that has never joined a keyset also enrolls it under its base UID.

### Scheduler identity and permissions

| Item | Value |
| --- | --- |
| Identity | the first `hsm_admin` entry that is not `*`; `admin` when there is none |
| Permission check | the same `Create` check as a manual Re-Key: when `[roles] crypto_officer_users` (deprecated: `privileged_users`) is set, the identity must be listed there, be the default user or hold a `Create` grant; otherwise every tick fails with `Permission_Denied` |
| Scope | only the keyset head; a failing key does not stop the rotation of the others |
| Renewal warnings | `info!` log events 30, 7 and 1 days before `CKA_END_DATE`, as for SQL keys |
| Scheduler activation | see [Enable the scheduler](auto_rotation_policy.md#enable-the-scheduler) |

### HSM model support

Auto-rotation needs an HSM that stores `CKA_START_DATE` and `CKA_END_DATE` on keys; see the `CKA_START_DATE`/`CKA_END_DATE` row of the [vendor quirks table](../../hsm_support/algorithm_support.md#vendor-specific-quirks). Idemia SPHERE, which is not in that table, does not store them either. On these HSMs, `SetAttribute RotateInterval` fails with:

```text
This HSM does not support CKA_START_DATE/CKA_END_DATE on keys; HSM key rotation scheduling is unavailable
```

Manual Re-Key and keyset addressing do not need key dates; they work on these HSMs too, for the algorithms the HSM can generate.

## Attribute support

| Request | HSM key behavior |
| --- | --- |
| `SetAttribute RotateName` | must equal the base UID; writes the generation-0 label `{rotate_name}::0::{key_id}@latest` |
| `SetAttribute RotateInterval` > 0 | arms auto-rotation: writes the dates, then enrolls the key under its base UID if it is not in a keyset yet (see [Rotation schedule](#rotation-schedule)) |
| `SetAttribute RotateInterval` > 0 on a public key | refused, `Invalid_Field` (set it on the private key) |
| `SetAttribute RotateInterval` = 0 | disarms auto-rotation (clears the dates, or writes a zero-length validity on a token that cannot unset a date; keeps keyset membership) |
| `SetAttribute RotateAutomatic` | refused, `Feature_Not_Supported`: use `RotateInterval` to arm or disarm |
| `SetAttribute RotateOffset` | refused, `Feature_Not_Supported` |
| `x-rotate-*` attributes in `Create` / `CreateKeyPair` | refused, `Feature_Not_Supported`; the message asks to set the rotation policy with `SetAttribute` after creation |

## Re-Key and Re-Key Key Pair

| Item | HSM behavior |
| --- | --- |
| Supported keys | AES keys (`Re-Key`, `C_GenerateKey`); RSA and EC key pairs (`Re-Key Key Pair` on the private key, `C_GenerateKeyPair`) |
| Where | same HSM slot as the old key |
| New UID | `{base UID}@{N+1}`; for a pair the public key is that UID + `_pk` |
| Old key | label retired (no `@latest`); no KMIP state change on the token |
| New key | label `…::{N+1}::{key_id}@latest`; dates re-stamped with the previous interval |
| KMIP links | no `ReplacementObjectLink` / `ReplacedObjectLink` |
| Dependent keys | database keys wrapped by the old HSM key (the old public key for a pair) are re-wrapped under the new one |
| `Offset`, `Attributes`, Protection Storage Masks | refused, `Feature_Not_Supported` |
| Permissions | server-level `Create` check, then the per-object `Rekey` permission; for a pair, `Rekey` on the public key too |

## Errors

| Error reason | Cause |
| --- | --- |
| `Item_Not_Found` | the key or keyset does not exist, including a Re-Key on an explicit `@N` that does not exist, or the caller holds no grant at all on it |
| `Object_Not_Found` | `Re-Key Key Pair` cannot retrieve the matching public key, or the caller lacks `Rekey` on that public key |
| `Permission_Denied` | the caller holds some grant on the key but not `Rekey`, or fails the `Create` check |
| `Invalid_Object_Type` | `Re-Key` on a private or public key; `Re-Key Key Pair` on an AES key or a public key. Checked after the `Rekey` permission |
| `Invalid_Field` | `Re-Key` of an addressed generation that is not the head (`is not the latest in its keyset`); keyset name other than the base UID; interval below one day; interval on a public key; generation counter at its maximum |
| `Wrong_Key_Lifecycle_State` | Encrypt, Sign or MAC with a retired generation |
| `Feature_Not_Supported` | `RotateOffset`, `RotateAutomatic`, `x-rotate-*` in Create, Re-Key `Offset`/`Attributes`/masks; bare-name Decrypt with a mode that cannot detect a wrong key |
| `Object_Already_Exists` | generation N+1 already exists on the slot, typically left by a rotation whose label writes did not all succeed; see [Recover from an interrupted rotation](hsm_keysets_how_to.md#recover-from-an-interrupted-rotation) |

## Differences from SQL keysets

| Aspect | SQL keysets | HSM keysets |
| --- | --- | --- |
| Keyset metadata | `x-rotate-*` attributes in the database | `CKA_LABEL`, `CKA_START_DATE`, `CKA_END_DATE` on the token |
| Keyset name | the generation-0 UID | the generation-0 base UID `hsm::<model>::<slot>::<key_id>` |
| Schedule | `x-rotate-interval`, `x-rotate-offset`, `x-rotate-automatic` | `RotateInterval` only, day granularity; due only with a keyset label plus both dates |
| Old key after rotation | `Deactivated` (KMIP state stored) | treated as `Deactivated` for protection; nothing stored |
| KMIP links | `ReplacedObjectLink` / `ReplacementObjectLink` | none |
| Concurrent re-key | version-conditional commit, loser gets `Conflict` | no object version; see [Concurrent Re-Key and Conflicts](concurrent_rekey.md) |
| Chain discovery | database query | slot scan of `CKA_LABEL` |

!!! warning "Protection checks require live token reads"
    Encrypt, Sign and MAC validate the keyset head against the token, not a cached generation list. Each protection operation scans the slot and reads the keyset metadata; the number of PKCS#11 round trips grows with the number of objects on that slot. Size slots and provision token capacity accordingly. A failed scan is an error, never permission to use a retired key.

SQL keyset behavior is described in [Key Rotation](index.md#keysets) and [Auto-Rotation Policy](auto_rotation_policy.md).
