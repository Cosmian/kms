## Getting a cert with certbot

### Install

#### MacOS

```sh
brew install certbot
```

#### Linux

```sh
apt install certbot
```

### Getting a cert using a TXT record

You must be able to edit the DNS records of the domain.
Run:

```sh
sudo certbot certonly -d test.cosmian.net --manual --preferred-challenges dns
```

and follow the printed instructions.

## Generating a PKCS#12 from the PEMs

```sh
openssl pkcs12 -export \
    -in test.cosmian.net.fullchain.pem \
    -inkey test.cosmian.net.privkey.pem \
    -out test.cosmian.net.p12
```
