The server can serve requests using either plaintext HTTP or HTTPS.

When running in a zero-trust environment, the KMS server should be started using HTTPS.
Check the [running in a zero-trust environment](./zero_trust.md) section for more information.

To enable TLS, one can provide certificates on the command line interface.

### Providing certificates

The key and full certificate chain must be available in a [PKCS#12](https://en.wikipedia.org/wiki/PKCS_12) format.

There are 2 ways to provide the PKCS#12 file to the server:

- using the KMS server start command line  `--https-p12-file` and `--https-p12-password` options
- setup certificates on the Cosmian VM

#### Configuring HTTPS via the command line

Specify the certificate name and mount the file to docker.

Say the certificate is called `server.mydomain.com.p12`, is protected by the password `myPass`, and is in a directory called `/certificate` on the host disk.

```sh
docker run --rm -p 443:9998 \
  -v /certificate/server.mydomain.com.p12:/root/cosmian-kms/server.mydomain.com.p12 \
  --name kms ghcr.io/cosmian/kms:4.19.3 \
  --database-type=mysql \
  --database-url=mysql://mysql_server:3306/kms \
  --https-p12-file=server.mydomain.com.p12 \
  --https-p12-password=myPass
```

!!!info "Generate a PKCS#12 from PEM files"
    To generate a PKCS12 from PEM files, you can use `openssl`:

    ```sh
    openssl pkcs12 -export \
    -in server.mydomain.com.fullchain.pem \
    -inkey server.mydomain.com.privkey.pem \
    -out server.mydomain.com.p12
    ```
