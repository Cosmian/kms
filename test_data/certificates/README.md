
The [generate.sh](./generate_certs.sh) script will generate

- a CA certificate
- a server certificate in a PKCS12 file to enable HTTPS on the server
- a client certificate to authenticate to the server with CN being <test.client@cosmian.com>

Since the PKCS12 password is `password` (see script), the following command will start the server:

```sh
RUST_LOG="cosmian=debug" cargo run --bin cosmian_kms -- \
    --https-p12-file ./crate/cli/test_data/certificates/kmserver.cosmian.com.p12 --https-p12-password password \
    --authority-cert-file ./crate/cli/test_data/certificates/ca.crt
```

The following command will test a client connection with client cert authentication:

```sh
curl -k --cert ./crate/cli/test_data/certificates/owner.client.cosmian.com.crt --key ./crate/cli/test_data/certificates/owner.client.cosmian.com.key https://localhost:9998/objects/owned
```
