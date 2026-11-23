## Features

### KMIP

- Add `cosmian_kmip::Sensitive<T>` (aliases `SensitiveBytes`, `SensitiveString`): a zeroizing wrapper whose `Debug` and `Display` print only the size (`<N bytes>`), with a transparent serde representation (wire format and stored JSON unchanged). Secret-bearing KMIP fields now use it, so a derived `Debug`/`Display` of a request can no longer print them: `Encrypt`/`Decrypt` data, IV, AAD and tag, `PKCS11` input and output parameters, `DerivationParameters` IV, salt and derivation data, `DecryptedData`, `Sign` data, and the key bytes of `KeyValue`/`KeyMaterial` (KMIP 1.4 and 2.1) ([#1426](https://github.com/Cosmian/kms/issues/1426))
- `Sensitive<T>`, `Secret<LENGTH>` and `SafeBigInt` compare in constant time

## Bug Fixes

### Hardening

- Hand-written redacting `Debug` for `SafeBigInt`, `Secret<LENGTH>`, `TTLValue` (byte strings and big integers), `CredentialValue` (passwords, one-time and hashed passwords, tickets), `KmipBigInt`, `KmipBigIntDeserializer`, `DataToEncrypt`, `BulkData`, and the HSM `KeyMaterial`, `RsaPrivateKeyMaterial` and `EcPrivateKeyMaterial`
- Trace and debug logs no longer print secrets: the TTLV serializer stack dumps and `#[instrument]` span fields (private-key big-integer limbs reached trace logs through them), the TTLV deserializer `TextString` and `ByteString` traces and the error messages echoing hex input, the symmetric decrypt trace (ciphertext, nonce, AAD, tag), the Covercrypt AAD logs and refreshed user key, the `ckms sym encrypt` client-side DEK trace, the `ckms certificates import/export` PKCS#12 password trace, the Azure EKM wrap/unwrap request, the Microsoft DKE encrypted data, and the PKCS#11 provider (`parse_mechanism`, attributes, encrypt/decrypt/sign/verify/MAC contexts, data objects)
- The PKCS#12 password no longer reaches trace logs: `Link` `Debug`/`Display` and `TTLV` `Debug` hide the target of a `PKCS12PasswordLink` (and, in `TTLV`, every `LinkedObjectIdentifier` text value), the `EncryptionKeyInformation` identifier (where `ckms certificates export --pkcs12-password` puts the password) is hidden in its `Debug`/`Display`, and `TTLV` `Debug` hides every `UniqueIdentifier` text value, and the object-retrieval trace logs the size of the object handle instead of its value
- `TTLV` `Debug` (traced as `{:?}` for the whole incoming request) hides the value of credential password tags (`Password`, `OneTimePassword`, `HashedPassword`, `TicketValue`)
- `ttlv_parser` output (`{:#?}` of a TTLV) now shows byte strings and big integers as sizes only
- Zeroize the KMIP 1.4 `Encrypt` and `DecryptResponse` data and `DerivationParameters` derivation data, and `DataToEncrypt` plaintext, which were plain `Vec<u8>`

## Refactor

### KMIP

- Rust API change for crates building the retyped structs: use `.into()` (`From<Vec<u8>>`, `From<Zeroizing<Vec<u8>>>`) to build a `SensitiveBytes`, and `into_zeroizing()` / `to_zeroizing()` to get a `Zeroizing<Vec<u8>>` back

---

Closes #1426
