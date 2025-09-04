The KMS activates two internal listeners: a socket server and an HTTP server.

The socket server listens to KMIP binary requests on the IANA-registered 5696 port.
The socket server will only start if the TLS configuration is provided **and** client certificate authentication is
enabled.

The HTTP server listens to KMIP requests on the `/kmip` and `/kmip/2_1` endpoints.
It also serves the web UI on the `/ui` endpoint.
The HTTP server is always started, even if the TLS configuration is not provided.

The KMS server should be started using HTTPS when running in a zero-trust environment.
Check the [running in a zero-trust environment](installation/marketplace_guide.md) section for more information.

To enable TLS, one can provide certificates on the command line interface.

### Providing certificates

The key and full certificate chain must be available in a [PKCS#12](https://en.wikipedia.org/wiki/PKCS_12) format to
serve TLS. The password to open the PKCS#12 file must also be provided.

When enabling client certificate authentication, the server's authority X509 certificate in PEM format must also be
provided. Multiple CA certificates can be concatenated in a single PEM file to support different certificate authorities.

### Configuration using the TOML configuration file

Certificate information must be provided in the `[tls]` section of the TOML configuration file.

```toml
# TLS configuration of the Socket server and HTTP server
[tls]

# The KMS server's optional PKCS#12 Certificates and Key file.
# If provided, this will start the server in HTTPS mode.
tls_p12_file = "[tls p12 file]"

# The password to open the PKCS#12 Certificates and Key file.
tls_p12_password = "[tls p12 password]"

# The server's optional authority X509 certificate in PEM format
# used to validate the client certificate presented for authentication.
# If provided, clients must present a certificate signed by this authority for authentication.
# The server must run in TLS mode for this to be used.
# Multiple CA certificates can be concatenated in a single PEM file.
clients_ca_cert_file = "[authority cert file]"

# Optional colon-separated list of TLS cipher suites to enable.
# If not specified, OpenSSL default cipher suites will be used.
# Example: "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"
# ANSSI-recommended cipher suites:
# - For TLS 1.3 (preferred): TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256
# - For TLS 1.2 (compatibility): TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
tls_cipher_suites = "[cipher suites]"
```

#### Configuring using the command line

Certificate information can be provided using the command line interface.

```bash
# The KMS server's optional PKCS#12 Certificates and Key file.
# If provided, this will start the server in HTTPS mode.
--tls-p12-file "[tls p12 file]"

# The password to open the PKCS#12 Certificates and Key file.
--tls-p12-password "[tls p12 password]"

# The server's optional authority X509 certificate in PEM format
# used to validate the client certificate presented for authentication.
# If provided, clients must present a certificate signed by this authority for authentication.
# The server must run in TLS mode for this to be used.
# Multiple CA certificates can be concatenated in a single PEM file.
--clients-ca-cert-file "[authority cert file]"

# Optional colon-separated list of TLS cipher suites to enable.
# If not specified, OpenSSL default cipher suites will be used.
# Example: "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"
--tls-cipher-suites "[cipher suites]"
```

!!!info "Generate a PKCS#12 from PEM files"
    To generate a PKCS12 from PEM files, you can use `openssl`:

```sh
openssl pkcs12 -export \
-in server.mydomain.com.fullchain.pem \
-inkey server.mydomain.com.privkey.pem \
-out server.mydomain.com.p12
```

## Advanced TLS Configuration

### TLS Cipher Suites Selection

The KMS server supports custom TLS cipher suite configuration to meet specific security requirements.
You can specify which cipher suites to enable using a colon-separated list.

The cipher suites are automatically categorized into TLS 1.3 and TLS 1.2 suites:

- **TLS 1.3 cipher suites** (preferred): `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_CCM_SHA256`, `TLS_AES_128_CCM_8_SHA256`
- **TLS 1.2 cipher suites** (for compatibility): `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`,
  `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`,
  `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`

If only TLS 1.3 cipher suites are specified, the server will enforce TLS 1.3 minimum protocol version.
If only TLS 1.2 cipher suites are specified, the server will support TLS 1.2 and above.

**Example configurations:**

```bash
# ANSSI-recommended TLS 1.3 only configuration
--tls-cipher-suites "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"

# Mixed TLS 1.2/1.3 configuration for compatibility
--tls-cipher-suites "TLS_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
```

### Multiple Certificate Authorities

The KMS server supports multiple certificate authorities for client certificate validation.
You can concatenate multiple CA certificates in PEM format into a single file.

**Example of multiple CA certificates in one file:**

```pem
-----BEGIN CERTIFICATE-----
[First CA Certificate]
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
[Second CA Certificate]
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
[Third CA Certificate]
-----END CERTIFICATE-----
```

This allows clients with certificates issued by any of the specified CAs to authenticate successfully.
The server will validate client certificates against all provided CA certificates.
