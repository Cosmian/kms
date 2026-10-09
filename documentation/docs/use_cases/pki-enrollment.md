# Device enrollment: EST and SCEP

The KMS can issue certificates to IoT fleets and MDM-managed devices with two standard
enrollment protocols: **EST** ([RFC 7030](https://www.rfc-editor.org/rfc/rfc7030)) and
**SCEP** ([RFC 8894](https://www.rfc-editor.org/rfc/rfc8894)). Both issue through the same
`Certify` operation as the rest of the PKI, signed by a CA certificate stored in the KMS, and are
constrained by a **certificate template**. Both are disabled by default.

## Prerequisites

Create a CA with the KMS and note its certificate unique identifier. The CA private key must be
`Active` and owned by `default_username`. For SCEP, the CA must be an RSA CA, since requests are
encrypted to the CA public key.

```sh
cat > ca.ext <<'EOF2'
[ v3_ca ]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,crlSign,digitalSignature,keyEncipherment
EOF2
ckms certificates certify --certificate-id device-ca --generate-key-pair --algorithm rsa2048 \
  --subject-name "CN=Device CA,O=ACME,C=FR" --days 3650 --certificate-extensions ca.ext
```

## Certificate templates

A template is a TOML section `[templates.<name>]` referenced by `est_template` / `scep_template`:

```toml
[templates.iot_device]
min_rsa_key_bits = 2048
allowed_ec_curves = ["prime256v1"]   # empty = any EC curve
allowed_ekus = ["clientAuth"]        # names or dotted OIDs; injected when the CSR has none
max_validity_days = 365
default_validity_days = 90
subject_cn_regex = "[a-z0-9-]+\\.iot\\.example"   # anchored: must match the whole value
san_dns_regex = "[a-z0-9-]+\\.iot\\.example"
```

Unknown keys in a template are rejected at startup, as are `min_rsa_key_bits` below 2048 and
inconsistent validity limits. Neither protocol carries a requested validity, so issued
certificates get `default_validity_days`. Checks applied to every CSR: proof of possession, key type and size, requested EKUs, no
`basicConstraints` `CA:TRUE`, subject CN and SAN patterns (when any SAN pattern is set, SAN types without a
pattern are refused), and validity clamped to `max_validity_days`. Violations answer
`422` (EST) or a `badRequest` `CertRep` (SCEP). Without a template, a baseline applies: RSA ≥ 2048,
no `CA:TRUE`, validity ≤ 365 days.

## EST

```toml
[est]
est_enabled = true
est_ca_uid = "<ca certificate uid>"
est_require_client_cert = true       # false enables the HTTP Basic bootstrap below
# est_bootstrap_username = "..."
# est_bootstrap_password = "..."
est_template = "iot_device"
```

| Route | Authentication | Purpose |
| --- | --- | --- |
| `GET /.well-known/est/cacerts` | none | CA chain as base64 certs-only PKCS#7 |
| `GET /.well-known/est/csrattrs` | none | CSR attributes (`204` without template) |
| `POST /.well-known/est/simpleenroll` | TLS client certificate, or HTTP Basic bootstrap | Initial enrollment |
| `POST /.well-known/est/simplereenroll` | TLS client certificate being renewed | Renewal / rekey, no secret needed |

EST must be served over TLS (RFC 7030). The KMS does not enforce this: with
`est_require_client_cert = false` on a plain-HTTP listener the Basic credentials travel in clear
text, and a warning is logged at startup. For re-enrollment the device certificate must be accepted by
the TLS layer: set `clients_ca_cert_file` to the EST CA certificate. Note that this enables mutual TLS
server-wide, so every device certificate also authenticates to the KMS API as the user named by its CN;
prefer a dedicated trust anchor for TLS client authentication where possible. The renewal CSR must
carry the same Subject and SubjectAltName as the certificate, which must be issued by the EST CA and
still `Active`. `/simpleenroll` applies the same identity rule when the client presents a certificate
issued by the EST CA.

## SCEP

```toml
[scep]
scep_enabled = true
scep_ca_uid = "<rsa ca certificate uid>"
scep_challenge_password = "<shared secret>"
scep_allow_renewal_without_challenge = true
scep_template = "iot_device"
```

`/scep` serves `GetCACaps` (`POSTPKIOperation`, `SHA-256`, `AES`, `Renewal`), `GetCACert` and
`PKIOperation`. An initial `PKCSReq` must carry the challenge password. A `RenewalReq` is signed
with a certificate previously issued by the SCEP CA that is within its validity period and `Active`
(not revoked); it needs no challenge and must keep the Subject and SubjectAltName of that
certificate. `DES3` and `SHA-1` are not supported: clients must negotiate `AES` and `SHA-256`.
The implementation is designed for clients that honour `GetCACaps`, as the Apple and Windows MDM SCEP
payloads are documented to; it is verified only against the micromdm `scepclient`, whose stock build
hard-codes single DES and needs AES-128-CBC selected (see `mise run test:scep-interop`). Apple and
Windows clients themselves were not run.

Limitations: `GetCert`, `GetCRL`, `CertPoll` and `GetNextCACert` are not implemented, and issuance is
synchronous (`PENDING` is never returned).

## Verifying the setup

- `mise run test:scep-interop`: micromdm `scepclient` enrollment, challenge-less renewal, wrong
  challenge, and an Apple `com.apple.security.scep` profile (macOS).
- `mise run test:est-interop`: globalsign `estclient` over TLS: `cacerts`, `csrattrs`,
  `enroll`, mTLS `reenroll` and rejections.
