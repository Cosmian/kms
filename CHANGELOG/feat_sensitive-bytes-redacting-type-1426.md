## Security

### KMIP

- Add `cosmian_kmip::Sensitive<T>` (aliases `SensitiveBytes`, `SensitiveString`): a zeroizing wrapper whose `Debug` and `Display` print only the size (`<N bytes>`), with a transparent serde representation (wire format unchanged). Secret-bearing KMIP fields now use it, so a derived `Debug`/`Display` of a request can no longer print them: `Encrypt`/`Decrypt` data, IV, AAD and tag, `PKCS11` input and output parameters, `DerivationParameters` IV, salt and derivation data, `DecryptedData`, `Sign` data, and the key bytes of `KeyValue`/`KeyMaterial` (KMIP 1.4 and 2.1) (#1426)
- Hand-written redacting `Debug` for `SafeBigInt`, `Secret<LENGTH>`, `TTLValue` (byte strings and big integers) and `CredentialValue` (passwords, one-time and hashed passwords, tickets)
- Rust API change for crates building these structs: use `.into()` (`From<Vec<u8>>`, `From<Zeroizing<Vec<u8>>>`) to build a `SensitiveBytes`, and `into_zeroizing()` / `to_zeroizing()` to get a `Zeroizing<Vec<u8>>` back
