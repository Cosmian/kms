# KMIP socket server: reject clients without a certificate during the TLS handshake

## Bug Fixes

- The KMIP socket server now sets `FAIL_IF_NO_PEER_CERT`, so a TLS client presenting no certificate is rejected during the handshake instead of after the first KMIP bytes are received ([#1276](https://github.com/Cosmian/kms/issues/1276)). The HTTP server is unchanged: client certificates stay optional there.

---

Closes #1276
