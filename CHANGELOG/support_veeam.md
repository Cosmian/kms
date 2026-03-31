# Veeam Backup KMIP Integration

## Bug Fixes

### KMIP Socket Server

- **TLS session resumption failure with mTLS clients**: the TCP socket server (`cosmian_kms_server::socket_server`) was missing a call to `SSL_CTX_set_session_id_context`. When client certificate verification (`SSL_VERIFY_PEER`) is enabled alongside the default TLS session cache, OpenSSL requires a session ID context to be set; without it any session-resumption attempt aborts with `error:0A000115:SSL routines:ssl_get_prev_session:session id context uninitialized`. Fixed by calling `builder.set_session_id_context(b"cosmian_kms_socket")` in `create_openssl_acceptor` before building the acceptor.

### KMIP 1.x Protocol (Veeam Backup compatibility)

- **`KmipUnexpectedTagException` when Veeam Backup decodes a `Get` response for an asymmetric key**: Cosmian KMS was embedding all object-metadata attributes (including `Link`, `UniqueIdentifier`, `State`, `Name`, etc.) inside the `KeyValue` structure of the returned key object. KMIP 1.x clients such as Veeam Backup do not expect these non-cryptographic attributes inside `KeyValue` and fail with `Unexpected Tag 66, expected Attribute`. Fixed by stripping all embedded `KeyValue` attributes for `PublicKey` and `PrivateKey` objects in KMIP 1.x `Get` responses (`perform_response_tweaks` in `routes/kmip.rs`). Cryptographic metadata (algorithm, length) is still exposed at the `KeyBlock` level.
