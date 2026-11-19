## Security

### KMIP

- Add `cosmian_kmip::Sensitive<T>` (aliases `SensitiveBytes`, `SensitiveString`): a zeroizing wrapper whose `Debug` and `Display` print only the size (`<N bytes>`), with a transparent serde representation (wire format unchanged). Secret-bearing KMIP fields now use it, so a derived `Debug`/`Display` of a request can no longer print them: `Encrypt`/`Decrypt` data, IV, AAD and tag, `PKCS11` input and output parameters, `DerivationParameters` IV, salt and derivation data, `DecryptedData`, `Sign` data, and the key bytes of `KeyValue`/`KeyMaterial` (KMIP 1.4 and 2.1) (#1426)
- Hand-written redacting `Debug` for `SafeBigInt`, `Secret<LENGTH>`, `TTLValue` (byte strings and big integers) and `CredentialValue` (passwords, one-time and hashed passwords, tickets)
- Rust API change for crates building these structs: use `.into()` (`From<Vec<u8>>`, `From<Zeroizing<Vec<u8>>>`) to build a `SensitiveBytes`, and `into_zeroizing()` / `to_zeroizing()` to get a `Zeroizing<Vec<u8>>` back
- `Sensitive<T>` compares in constant time (`PartialEq`/`Eq`, also against the plain value)
- Hand-written redacting `Debug` also for `KmipBigInt`, `KmipBigIntDeserializer`, `DataToEncrypt` and `BulkData`
- Trace and debug logs no longer print secrets: the TTLV deserializer ByteString trace, the TTLV serializer `#[instrument]` span fields of byte, string and integer values, the symmetric decrypt trace (ciphertext, nonce, AAD, tag), the Covercrypt AAD logs, the `ckms sym encrypt` client-side DEK trace and the PKCS#11 `parse_mechanism` IV
- `ttlv_parser` output (`{:#?}` of a TTLV) now shows byte strings and big integers as sizes only
- `TTLV` `Debug` (traced as `{:?}` for the whole incoming request) hides the value of credential password tags (`Password`, `OneTimePassword`, `HashedPassword`, `TicketValue`)
