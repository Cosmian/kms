# X25519 key agreement for share sealing

This how-to shows how to keep X25519 private keys, the intermediate shared secret, and the final sealing key inside the KMS.

This workflow is available only in `non-fips` builds.

## 1. Create the two X25519 key pairs

Create one X25519 key pair for each party with `CryptographicAlgorithm = ECDH` and `RecommendedCurve = CURVE25519`.

The test vector `test_data/vectors/non-fips/derive_key_x25519/step1_create_alice_keypair.json` uses this request shape:

```json
{
  "tag": "CreateKeyPair",
  "value": [
    {
      "tag": "CommonAttributes",
      "value": [
        {"tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "ECDH"},
        {
          "tag": "CryptographicDomainParameters",
          "value": [
            {"tag": "RecommendedCurve", "type": "Enumeration", "value": "CURVE25519"}
          ]
        },
        {"tag": "CryptographicUsageMask", "type": "Integer", "value": 2560}
      ]
    }
  ]
}
```

The usage mask above combines `DeriveKey` and `KeyAgreement` for the private key and lets the server create the linked public key for the same curve.

## 2. Derive the shared secret with `DeriveKey`

Send `DerivationMethod = Asymmetric_Key` with two repeated `ObjectUniqueIdentifier` fields.

The first identifier must reference the X25519 private key.

The second identifier must reference the peer X25519 public key.

The derived object is always stored as `SecretData`.

```json
{
  "tag": "DeriveKey",
  "value": [
    {"tag": "ObjectType", "type": "Enumeration", "value": "SecretData"},
    {"tag": "ObjectUniqueIdentifier", "type": "TextString", "value": "{{alice_private_key_id}}"},
    {"tag": "ObjectUniqueIdentifier", "type": "TextString", "value": "{{bob_public_key_id}}"},
    {"tag": "DerivationMethod", "type": "Enumeration", "value": "Asymmetric_Key"},
    {"tag": "DerivationParameters", "value": []},
    {
      "tag": "Attributes",
      "value": [
        {"tag": "CryptographicLength", "type": "Integer", "value": 256},
        {"tag": "ObjectType", "type": "Enumeration", "value": "SecretData"}
      ]
    }
  ]
}
```

The stored shared secret is marked sensitive, non-extractable, and linked back to both base objects.

## 3. Expand the shared secret into a sealing key

Use a second `DeriveKey` call with `DerivationMethod = HKDF` when you need an application sealing key.

The server-side tests derive a 256-bit `ChaCha20Poly1305` key from the stored shared secret before encrypting a payload.

This keeps the raw X25519 shared secret separate from the symmetric key that performs encryption.

## 4. Encrypt and decrypt with `ChaCha20Poly1305`

Use the derived symmetric key with the existing `Encrypt` and `Decrypt` operations.

Activate each HKDF-derived key with `Activate` before using it for encryption or decryption — keys derived by `DeriveKey` are created in the `PreActive` state, and `Encrypt`/`Decrypt` require an `Active` key.

The current path already supports `ChaCha20Poly1305`, so no new symmetric algorithm is required for this workflow.

Use a unique 12-byte `IVCounterNonce` for every encryption under a given sealing key, backed by a persisted monotonic counter or another collision-free per-key construction. Reusing a nonce across two encryptions under the same key breaks ChaCha20-Poly1305's keystream and one-time authentication key, exposing plaintext relationships and weakening authentication.

When you build a share-sealing protocol on top of the KMS, put protocol context in `AuthenticatedEncryptionAdditionalData`.

Recommended AAD inputs include a protocol or version label, a deposit identifier, a share index, a holder identifier, and the ephemeral public key identifier that selected the peer key.

## 5. Destroy intermediates after use

Destroy the derived `SecretData` object when the sealing key has been expanded or rotated away.

Destroy or revoke the resulting symmetric sealing key when the share lifecycle ends.

The server tests cover this full flow by deriving the X25519 secret, deriving a `ChaCha20Poly1305` key through HKDF, encrypting and decrypting a small payload, and then destroying the sealing keys to verify later use fails.
