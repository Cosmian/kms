## Bug Fixes

### Hardening

- AWS XKS: the SigV4 middleware rejects request bodies above 2 MiB (HTTP 413) while reading them, before signature verification, and no longer turns body read errors into an empty body (HTTP 400) ([#1488](https://github.com/Cosmian/kms/issues/1488))
- OCSP responder: a request resolves all its `CertID`s with one certificate scan instead of one per `CertID`, and cache misses (nonce, multi-`CertID`) are limited to one lookup and signature per CPU at a time ([#1488](https://github.com/Cosmian/kms/issues/1488))
- KMIP socket server: the 256 MiB in-flight budget is reserved as request bytes arrive instead of for the declared length, so slow clients announcing 64 MiB frames can no longer exhaust it ([#1488](https://github.com/Cosmian/kms/issues/1488))

---

Closes #1488
