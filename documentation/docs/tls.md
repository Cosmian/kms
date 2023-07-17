The server can serve requests using either plaintext HTTP or HTTP/S.

To enable TLS, one can install certificates or use the certificates bot `certbot` to fetch and renew the certificates automatically.

### Installing certificates

The certificate (key and full chain) must be available in a PKCS#12 format.
Specify the certificate name and mount the file to docker.

Say the certificate is called `server.mydomain.com.p12`, is protected by the password `myPass`, and is in a directory called `/certificate` on the host disk.

```sh
docker run --rm -p 443:9998 \
  -v /certificate/server.mydomain.com.p12:/root/cosmian-kms/server.mydomain.com.p12 \
  --name kms ghcr.io/cosmian/kms:4.4.3 \
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

### Using the certificates bot

The Cosmian KMS server has support for a certificates bot that can automatically obtain and renew its certificates from Let's Encrypt using the `acme` protocol.

To enable the use of the certificate bot, enable the `--use-certbot` switch then specify

- the KMS hostname (Common Name in the certificate) using the `--certbot-hostname` option
- and the domain name owner email using the `--certbot-email` option, e.g.

The hostname must be a valid DNS A or AAAA record pointing to the IP address of this server, as the Let's Encrypt server will attempt to connect to the server during the process. Firewalls, if any, must be open.

By default, the bot saves the certificates inside the container in the `/root/cosmian-kms/certbot-ssl` directory. This directory is adjustable with the `--certbot-ssl-path` option. Ensure this directory is mapped to a host directory or persistent docker volume to persist the generated certificates between restarts.

Example:

```sh
docker run --rm -p 443:9998 \
  -v cosmian-kms:/root/cosmian-kms/sqlite-data \
  -v cosmian-kms-certs:/root/cosmian-kms/certbot-ssl \
  --name kms ghcr.io/cosmian/kms:4.4.3 \
  --database-type=sqlite-enc \
  --use-certbot \
  --certbot-server-name server.mydomain.com \
  --certbot-email admin@mydomain.com
```
