## Features

### API
- Prevent duplicate KV version allocation during concurrent writes, bind reads and hard deletes to the recorded path-owned version objects, reject reserved system tags during object import, and enforce SQL-compatible KV path limits and listing boundaries.
- Add KMS-managed short-lived OpenSSH certificate issuance and authorized password generation for external secret rotation ([#864](https://github.com/Cosmian/kms/issues/864)). Subject RSA keys must be at least 3072 bits.

### Documentation
- Document SSH CA setup, certificate issuance, and PostgreSQL-to-KV rotation recovery.
