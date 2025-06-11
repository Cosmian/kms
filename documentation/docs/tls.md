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
provided.

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
clients_ca_cert_file = "[authority cert file]"
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
--clients-ca-cert-file "[authority cert file]"
```

!!!info "Generate a PKCS#12 from PEM files"
To generate a PKCS12 from PEM files, you can use `openssl`:

    ```sh
    openssl pkcs12 -export \
    -in server.mydomain.com.fullchain.pem \
    -inkey server.mydomain.com.privkey.pem \
    -out server.mydomain.com.p12
    ```
