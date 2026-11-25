# HSM Key Rotation

Eviden KMS rotates keys that reside on a PKCS#11 HSM (Utimaco, Proteccio, Thales Luna, SoftHSM2, …) the same way it rotates database keys: manually with `Re-Key` (AES keys) and `Re-Key Key Pair` (RSA and EC key pairs), and on a schedule with the auto-rotation scheduler. The generations of a key form an **HSM keyset** addressed by the key's base UID `hsm::<model>::<slot>::<key_id>`; generation N is `hsm::<model>::<slot>::<key_id>@N`.

New keys are generated on the same HSM slot and cryptographic operations run on the token. The keyset state lives on the token too, in `CKA_LABEL` and `CKA_START_DATE` / `CKA_END_DATE`, with no database rows. Create non-extractable keys when key material must never be exportable.

| Page | Type | Read it to |
| --- | --- | --- |
| [How to rotate HSM keys](hsm_keysets_how_to.md) | How-to | enroll a key, arm or disarm auto-rotation, rotate keys and key pairs, use a keyset for cryptography, recover from an interrupted rotation |
| [HSM keysets reference](hsm_keysets_reference.md) | Reference | look up UID and `CKA_LABEL` formats, the addressing rules per operation, the due rule, attribute support, errors, HSM model support and the differences from SQL keysets |
| [HSM keysets explained](hsm_keysets_explanation.md) | Explanation | understand why the token carries the state, why old generations cannot protect data, why some decryption modes need an explicit generation and which identity the scheduler uses |

Rotation of database keys is described in [Key Rotation](index.md) and [Auto-Rotation Policy](auto_rotation_policy.md).
