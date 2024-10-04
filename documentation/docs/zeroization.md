# Zeroization

Secret keys and plaintexts are considered highly sensitive information and to securely erase from
memory or storage Cosmian KMS implements data `zeroization`.
The term `zeroization` originates from the process of setting all relevant bits to zero, effectively
rendering the data unreadable and unrecoverable.
This practice is essential to prevent unwanted memory residue of critical data,
especially in scenarios where the confidentiality and integrity of data are paramount.

This is particularly crucial in environments where multiple users or processes access the same
resources, but this does not prevent in any way an attacker reading from live memory as the latter
may not be encrypted.

It is good to notice that in the source code, only keys and plaintexts represented as byte arrays
are being *zeroized* using the [zeroize](https://docs.rs/zeroize/latest/zeroize/) crate.
Regarding OpenSSL `PKey` types, they are being zeroized by OpenSSL itself, which is triggered on
`drop` by Rust.

> EVP_PKEYs are dropped with EVP_PKEY_free, which should use the appropriate cipher-internal freeing
> function, which in turn should cleanse all private data unless there is a bug in the underlying
> OpenSSL library [...].
> [source](https://github.com/sfackler/rust-openssl/issues/2147)

## Regulatory Compliance

Cosmian KMS thus adheres to relevant industry standards and regulatory requirements concerning data
security and privacy such as the
[Rust guidelines from ANSSI](https://cyber.gouv.fr/publications/regles-de-programmation-pour-le-developpement-dapplications-securisees-en-rust).
The use of zeroization aligns with this standard, demonstrating our commitment to safeguarding
sensitive information and meeting the necessary compliance obligations.
