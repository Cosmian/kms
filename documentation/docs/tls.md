The server can serve requests using either plaintext HTTP or HTTPS.

When running in a zero-trust environment, the KMS server should be started using HTTPS.
Check the [running in a zero-trust environment](./zero_trust.md) section for more information.

To enable TLS, one can provide certificates - on the command line or via the bootstrap server - or use the certificates bot `certbot` to fetch and renew the certificates automatically.

### Providing certificates

The key and full certificate chain must be available in a [PKCS#12](https://en.wikipedia.org/wiki/PKCS_12) format.

There are 2 ways to provide the PKCS#12 file to the server:

- using the KMS server start command line  `--https-p12-file` and `--https-p12-password` options
- via the bootstrap server on a TLS connection when the KMS server is started in this mode. This is more secure than the command line.

A PKCS#12 file should be provided to the KMS server via the bootstrap server in a [zero-trust environment](./zero_trust.md).

#### Configuring HTTPS via the bootstrap server

Configuring HTTPS via the bootstrap TLS connection is described in [Bootstrapping the KMS server start](bootstrap.md).

#### Configuring HTTPS via the command line

Specify the certificate name and mount the file to docker.

Say the certificate is called `server.mydomain.com.p12`, is protected by the password `myPass`, and is in a directory called `/certificate` on the host disk.

```sh
docker run --rm -p 443:9998 \
  -v /certificate/server.mydomain.com.p12:/root/cosmian-kms/server.mydomain.com.p12 \
  --name kms ghcr.io/cosmian/kms:4.9.1 \
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

### Using the certificates' bot

The Cosmian KMS server has support for a certificates bot that can automatically obtain and renew its certificates from Let's Encrypt using the `acme` protocol.

To enable the use of the certificate bot, enable the `--use-certbot` switch then specify

- the KMS hostname (Common Name in the certificate) using the `--certbot-hostname` option
- and the domain name owner email using the `--certbot-email` option, e.g.

The hostname must be a valid DNS A or AAAA record pointing to the IP address of this server, as the Let's Encrypt server will attempt to connect to the server during the process. Firewalls, if any, must be open.

By default, the bot saves the certificates inside the container in the `/root/cosmian-kms/certbot-ssl` directory. This directory is adjustable with the `--certbot-ssl-path` option. Ensure this directory is mapped to a host directory or persistent docker volume to persist the generated certificates between restarts.

If the KMS runs inside a TEE, you can also use the option `--certbot-use-tee-key` following by an hexadecimal string standing for a salt in order to generate the TLS key using the TEE. The key is tied to the TEE starting parameters and the code. Two KMS instances from the same code and the same TEE parameters will generate the same TLS key for a given salt.

Example:

```sh
docker run --rm -p 443:9998 \
  -v cosmian-kms:/root/cosmian-kms/sqlite-data \
  -v cosmian-kms-certs:/root/cosmian-kms/certbot-ssl \
  --name kms ghcr.io/cosmian/kms:4.9.1 \
  --database-type=sqlite-enc \
  --use-certbot \
  --certbot-server-name server.mydomain.com \
  --certbot-email admin@mydomain.com
```
