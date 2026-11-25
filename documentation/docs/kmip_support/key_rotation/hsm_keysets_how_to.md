# How to rotate HSM keys

This guide shows how to put an HSM-resident key in a keyset, schedule its rotation, rotate it by hand, use it by keyset address and repair a failed rotation. The exact rules behind each step are in the [HSM keysets reference](hsm_keysets_reference.md).

## Prerequisites

- A KMS server configured with an HSM; see [HSM keys & operations](../../hsm_support/hsm_operations.md) and the page of your HSM model. The examples use the `utimaco` model on slot 0; replace the `hsm::utimaco::0::` prefix with yours (see [Multi-HSM support](../../hsm_support/multi_hsm.md)).
- `ckms` configured for a user listed in `hsm_admin`. The examples assume an HSM admin; for other users see [HSM key authorization model](../../hsm_support/hsm_operations.md#hsm-key-authorization-model).
- For scheduled rotation only: an HSM that stores `CKA_START_DATE` / `CKA_END_DATE` (see [HSM model support](hsm_keysets_reference.md#hsm-model-support)), and the scheduler enabled as described in [Enable the scheduler](auto_rotation_policy.md#enable-the-scheduler).

## Enroll an HSM key in a keyset

1. Create the key on the HSM, with its base UID as the key identifier:

    ```bash
    ckms sym keys create --algorithm aes --number-of-bits 256 hsm::utimaco::0::my-aes-key
    ```

2. Set the keyset name. For an HSM key it **must** be the key's base UID:

    ```bash
    ckms sym keys set-rotation-policy \
        --key-id hsm::utimaco::0::my-aes-key \
        --rotation-name hsm::utimaco::0::my-aes-key
    ```

    ```text
    Rotation policy set successfully.
        Unique identifier: hsm::utimaco::0::my-aes-key
    ```

    The key's `CKA_LABEL` becomes `hsm::utimaco::0::my-aes-key::0::my-aes-key@latest`.

For an RSA or EC key pair, run the same command with `ckms rsa keys` or `ckms ec keys` on the **private key** UID.

Explicit enrollment is optional: a key that never joined a keyset is enrolled under its base UID when you arm auto-rotation on it (see below) or at its first manual re-key.

## Arm or disarm auto-rotation

Arm the schedule by setting an interval of at least one day (86400 seconds) on the key, or on the private key of a pair. This example rotates every 30 days:

```bash
ckms sym keys set-rotation-policy --key-id hsm::utimaco::0::my-aes-key --interval 2592000
```

If the key is not in a keyset yet, setting the interval also enrolls it under its base UID. The scheduler rotates the key once today (UTC) reaches its `CKA_END_DATE`, then re-arms the new key with the same interval. Renewal warnings are logged 30, 7 and 1 days before.

Disarm it with an interval of `0`; the key stays in its keyset:

```bash
ckms sym keys set-rotation-policy --key-id hsm::utimaco::0::my-aes-key --interval 0
```

!!! warning "Options that HSM keys refuse"
    Do not pass `--offset` (`RotateOffset` is refused) and do not set `RotateAutomatic`: `--interval` alone arms and disarms the schedule. Do not set the interval on the public key of a pair.

## Rotate an HSM key manually

Rotate an AES key by naming its base UID; the server always rotates the keyset head:

```bash
ckms sym keys re-key --key-id hsm::utimaco::0::my-aes-key
```

```text
The symmetric key was successfully refreshed.
    Unique identifier: hsm::utimaco::0::my-aes-key@1
```

Each further `re-key` of the base UID returns `@2`, `@3`, and so on.

Rotate an RSA or EC key pair by naming the private key:

```bash
ckms rsa keys re-key --key-id hsm::utimaco::0::my-rsa-key
```

```text
The key pair was successfully rotated.
    Unique identifier: hsm::utimaco::0::my-rsa-key@1
```

The new public key is `hsm::utimaco::0::my-rsa-key@1_pk`.

Do not re-key an explicit old generation: once `@1` exists, `--key-id hsm::utimaco::0::my-aes-key@0` (or `@first`) fails with `Invalid_Field` and a message containing `is not the latest in its keyset`. Use the base UID or `@latest` instead.

## Encrypt, decrypt, sign and verify by keyset address

Encrypt with the base UID: the server uses the keyset head.

```bash
ckms sym encrypt --key-id hsm::utimaco::0::my-aes-key --output-file data.enc data.bin
```

Decrypt with the base UID: the server tries each generation, newest first, so data encrypted before a rotation still decrypts.

```bash
ckms sym decrypt --key-id hsm::utimaco::0::my-aes-key --output-file data.out data.enc
```

Decrypting with a mode that cannot detect a wrong key (for example `--data-encryption-algorithm aes-cbc`) is refused for the base UID. Name the generation that encrypted the data instead:

```bash
ckms sym decrypt --key-id hsm::utimaco::0::my-aes-key@1 --data-encryption-algorithm aes-cbc --output-file data.out data.enc
```

Sign with the private key's base UID and verify with the public key's base UID; verification tries every generation until one accepts the signature:

```bash
ckms rsa sign --key-id hsm::utimaco::0::my-rsa-key --output-file data.sig data.bin
ckms rsa sign-verify --key-id hsm::utimaco::0::my-rsa-key_pk data.bin data.sig
```

Encrypt, Sign and MAC with an old generation (`@0`, `@first`, or `@N` that is no longer the head) fail with `Wrong_Key_Lifecycle_State`. The full matrix is in [Addressing](hsm_keysets_reference.md#addressing).

!!! note "FIPS builds"
    AES-GCM Encrypt by keyset address runs on the HSM and fails on an HSM that cannot generate the GCM IV (for example SoftHSM2, Kryoptic). See [AES-GCM IVs and HSM FIPS mode](../../hsm_support/hsm_aes_gcm_iv.md).

## Recover from an interrupted rotation

A rotation writes several labels one after the other: the old head, the new key and, for a key pair, the two public keys. If it fails after generating the new key but before every label is written, the keyset is left half-rotated, and every further rotation fails with `Object_Already_Exists`:

```text
HSM key '<new uid>' already exists — generation <N> was already created on this HSM slot. …
```

Depending on where the rotation stopped, the new generation may already be in use: once the new private or AES key is labelled `@latest` it is the keyset head, so clients may have encrypted or signed with it, and database keys may have been re-wrapped under it, even though the public key labels were never updated. Do not destroy any generation before you know it is unused.

1. Note the `<new uid>` from the error message (for a scheduled rotation, the server log line starts with `[auto-rotate] Failed to rotate key`).
2. Stop writes to the keyset: disarm auto-rotation (`--interval 0`, see [Arm or disarm auto-rotation](#arm-or-disarm-auto-rotation)) and pause the applications that encrypt or sign with it.
3. Inspect the state of every generation and its public key: read `CKA_LABEL` with the vendor tools or `pkcs11-tool --list-objects`, and check whether data, signatures or database keys wrapped by the new generation exist.
4. Prefer repairing the labels over deleting keys: an HSM operator writes the missing labels with the vendor tools, in the format given in [`CKA_LABEL` format](hsm_keysets_reference.md#cka_label-format), so that the old head is retired and the new generation (and its public key) is labelled as the head.
5. Destroy a generation only when step 3 showed that nothing depends on it, then rotate again with `ckms sym keys re-key --key-id hsm::utimaco::0::my-aes-key` (or `ckms rsa keys re-key` for a pair).
6. Re-arm auto-rotation.
