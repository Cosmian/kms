# KMS Server — Obtaining TLS Certificates

Three paths are described below, from quickest to most production-ready.

---

## Path 1 — Auto-generate a self-signed PKI (recommended for quick start)

Run the interactive wizard and let it create a complete PKI for you:

```sh
cosmian_kms configure
```

At step 3/9 answer **Yes** to "Enable TLS?" and **Yes** to "Generate self-signed
certificates". The wizard prompts for:

| Prompt | Default | Notes |
|--------|---------|-------|
| Output directory | `/etc/cosmian/` | All PEM files are written here |
| CA Common Name | `Cosmian KMS CA` | Identifies the root CA |
| Server CN | `Cosmian KMS Server` | Must match the server's hostname for strict clients |
| Client CN | `Cosmian KMS Client` | Embedded in the client certificate subject |
| CA validity (days) | `3650` | ~10 years |
| Server validity (days) | `365` | Renew annually |
| Client validity (days) | `365` | Renew annually |

The wizard then asks whether to enable mutual TLS (mTLS). If yes, it sets
`clients_ca_cert_file` automatically so the server validates client certificates.

**Files written:**

| File | Purpose |
|------|---------|
| `ca.crt` | Root CA certificate — import into clients that must trust the server |
| `server.crt` | Server leaf certificate (signed by the CA) |
| `server.key` | Server private key (PKCS#8 PEM) |
| `client.crt` | Client leaf certificate — distribute to mTLS clients |
| `client.key` | Client private key (PKCS#8 PEM) |

At the end the wizard writes `kms.toml` and prints the start command.

> **Note:** Self-signed certificates are suitable for internal deployments and
> testing. For internet-facing or compliance-sensitive environments use a
> CA-signed certificate (see Path 2 below).

---

## Path 2 — Obtain a CA-signed certificate with certbot (production)

Use [certbot](https://certbot.eff.org/) to obtain a free certificate from
Let's Encrypt via a DNS challenge (no HTTP server required).

### 1. Install certbot

**macOS (Homebrew):**

```sh
brew install certbot
```

**Debian / Ubuntu:**

```sh
sudo apt install certbot
```

**RHEL / CentOS / Fedora:**

```sh
sudo dnf install certbot
```

### 2. Request a certificate using a DNS TXT record

You must have write access to the DNS zone for your domain.

```sh
sudo certbot certonly \
  --manual \
  --preferred-challenges dns \
  -d kms.example.com
```

Certbot prints a DNS TXT record to add under `_acme-challenge.kms.example.com`.
Add it through your DNS provider's control panel, wait for propagation (usually
60–120 s), then press Enter to continue.

Certbot writes the certificate files under `/etc/letsencrypt/live/kms.example.com/`:

| File | Description |
|------|-------------|
| `fullchain.pem` | Server certificate + intermediate chain |
| `privkey.pem` | Server private key |

### 3. Reference the certificates in `kms.toml`

**FIPS mode (default build):**

```toml
[tls]
tls_cert_file = "/etc/letsencrypt/live/kms.example.com/fullchain.pem"
tls_key_file  = "/etc/letsencrypt/live/kms.example.com/privkey.pem"
```

**Non-FIPS mode** — convert to PKCS#12 first (see [Appendix](#appendix-converting-pem-to-pkcs12)), then:

```toml
[tls]
tls_p12_file     = "/etc/ssl/kms/kms.example.com.p12"
tls_p12_password = "your_password"
```

### 4. Renewal

Let's Encrypt certificates expire after 90 days. Automate renewal with a cron job
or systemd timer:

```sh
sudo certbot renew --quiet
```

Restart (or send `SIGHUP` to) the KMS server after renewal so it picks up the
new certificate.

---

## Path 3 — Bring your own certificates

If your organisation has its own PKI, place the PEM files where the server can
read them and point the TOML fields to them:

**FIPS mode (default build):**

```toml
[tls]
tls_cert_file  = "/etc/ssl/kms/server.crt"   # PEM, may include full chain
tls_key_file   = "/etc/ssl/kms/server.key"   # PKCS#8 or traditional PEM
# tls_chain_file = "/etc/ssl/kms/chain.pem"  # Optional separate chain file

# Uncomment to require client certificates (mTLS):
# clients_ca_cert_file = "/etc/ssl/kms/ca.crt"
```

**Non-FIPS mode:**

```toml
[tls]
tls_p12_file     = "/etc/ssl/kms/server.p12"
tls_p12_password = "your_password"
# clients_ca_cert_file = "/etc/ssl/kms/ca.crt"  # Optional mTLS CA
```

Run `cosmian_kms configure` and choose "Provide your own certificate paths" at
step 3/9 to have the wizard fill in these values interactively.

---

## Appendix: Converting PEM to PKCS#12

Required for non-FIPS mode when you have PEM files (e.g., from certbot or your own PKI):

```sh
openssl pkcs12 -export \
  -in  server.fullchain.pem \
  -inkey server.privkey.pem \
  -out server.p12
```

You will be prompted to set a password for the bundle. Use that password as
`tls_p12_password` in `kms.toml`.
