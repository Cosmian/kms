## Features

- Implement KMIP ReKey operation for symmetric keys with name transfer per §4.4
- Support re-wrapping of dependent keys when a wrapping key is rekeyed
- Add `find_wrapped_by()` method to `ObjectsStore` trait (SQLite, PostgreSQL, MySQL implementations)

## Bug Fixes

- Transfer `Name` attribute from old key to new key during ReKey per KMIP §4.4
- Return error instead of silently skipping when a user-supplied wrapping key ID equals the key being wrapped
- Bypass ownership check for server-configured KEK during wrapping operations

## Testing

- Add 9 symmetric ReKey test vectors (basic, wrapped, wrapping-key re-wrap, name transfer, offset, links)
- Add 27 ReKeyKeyPair test vectors (RSA, EC, ML-KEM, ML-DSA, SLH-DSA, X25519, secp256k1)
- Add access privilege escalation test vector for ReKey
