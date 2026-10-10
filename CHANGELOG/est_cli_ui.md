### EST client commands in `ckms` and the Web UI ([#871](https://github.com/Cosmian/kms/issues/871))

- Added `ckms est cacerts --out <file>`: downloads the CA chain from the public
  `GET /.well-known/est/cacerts` endpoint and writes it as concatenated PEM certificates.
- Added `ckms est enroll --csr <file> --out <file> [--csr-format pem|der] [--user <u> --password <p>]`:
  submits a PKCS#10 CSR to `POST /.well-known/est/simpleenroll` and writes the issued certificate as PEM.
  Authentication is the TLS client certificate configured in `ckms.toml`, or HTTP Basic bootstrap
  credentials (`--user`/`--password`), which are sent alone — the client's own KMS bearer token is not attached.
- Added `HttpClient::post_bytes_with_basic_auth` to `cosmian_kms_client`.
- Web UI: new **Certificates → Enrollment (EST)** menu with *CA Certificates* and *Enroll* pages.
  Unlike the CLI, the UI downloads the raw PKCS#7 (`.p7b`) response; extract PEM certificates with
  `openssl pkcs7 -inform DER -in <file> -print_certs`.
- `ckms est reenroll` and SCEP client commands are not provided.
