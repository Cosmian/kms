## Security

### KMIP

- Add `cosmian_kmip::Sensitive<T>` (aliases `SensitiveBytes`, `SensitiveString`): a zeroizing wrapper whose `Debug` and `Display` print only the size (`<N bytes>`), with a transparent serde representation (wire format unchanged). Secret-bearing KMIP fields now use it, so a derived `Debug`/`Display` of a request can no longer print them: `Encrypt`/`Decrypt` data, IV, AAD and tag, `PKCS11` input and output parameters, `DerivationParameters` IV, salt and derivation data, `DecryptedData`, `Sign` data, and the key bytes of `KeyValue`/`KeyMaterial` (KMIP 1.4 and 2.1) (#1426)
- Hand-written redacting `Debug` for `SafeBigInt`, `Secret<LENGTH>`, `TTLValue` (byte strings and big integers) and `CredentialValue` (passwords, one-time and hashed passwords, tickets)
- Rust API change for crates building these structs: use `.into()` (`From<Vec<u8>>`, `From<Zeroizing<Vec<u8>>>`) to build a `SensitiveBytes`, and `into_zeroizing()` / `to_zeroizing()` to get a `Zeroizing<Vec<u8>>` back
- `Sensitive<T>` compares in constant time (`PartialEq`/`Eq`, also against the plain value)
- Hand-written redacting `Debug` also for `KmipBigInt`, `KmipBigIntDeserializer`, `DataToEncrypt` and `BulkData`
- `Encrypt`/`Decrypt` retyping in KMIP 2.1 also covers `EncryptResponse.data` (it carries the KEM shared secret for hybrid KEM keys). KMIP 1.4 `Encrypt.data` and `DecryptResponse.data` stay `Vec<u8>` (that module has no derived `Debug` on them)
- Trace and debug logs no longer print secrets: the TTLV serializer stack dumps and `#[instrument]` span fields (private-key big-integer limbs reached trace logs through them), the TTLV deserializer `TextString` and `ByteString` traces and the error messages echoing hex input, the symmetric decrypt trace (ciphertext, nonce, AAD, tag), the Covercrypt AAD logs and refreshed user key, the `ckms sym encrypt` client-side DEK trace, the `ckms certificates import/export` PKCS#12 password trace, the Azure EKM wrap/unwrap request, the Microsoft DKE encrypted data, and the PKCS#11 provider (`parse_mechanism`, attributes, encrypt/decrypt/sign/verify/MAC contexts, data objects)
- `Link` `Debug`/`Display` and `TTLV` `Debug` hide the target of a `PKCS12PasswordLink` (it is the PKCS#12 password) and, in `TTLV`, every `LinkedObjectIdentifier` text value
- `Debug` of the HSM `KeyMaterial`, `RsaPrivateKeyMaterial` and `EcPrivateKeyMaterial` no longer prints key bytes
- `ttlv_parser` output (`{:#?}` of a TTLV) now shows byte strings and big integers as sizes only
- `TTLV` `Debug` (traced as `{:?}` for the whole incoming request) hides the value of credential password tags (`Password`, `OneTimePassword`, `HashedPassword`, `TicketValue`)
- `SensitiveString` has no production user yet; it is the type to use for new secret text fields
