# Public Key Infrastructure (PKI)

The Cosmian KMS is a full-featured X.509 certificate authority capable of issuing,
storing, validating, and revoking certificates for both **classical** and
**post-quantum** algorithms.

## Supported standards

| Standard | Description | Scope |
| -------- | ----------- | ----- |
| [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) | X.509 PKI Certificate and CRL Profile | All certificate operations |
| [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017) | PKCS #1 v2.2 — RSA Cryptography | RSA key pairs & certificates |
| [RFC 5480](https://www.rfc-editor.org/rfc/rfc5480) | ECC Subject Public Key Information | EC/ECDSA key pairs & certificates |
| [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) | Edwards-Curve Digital Signature Algorithm (EdDSA) | Ed25519/Ed448 certificates |
| [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881) | ML-DSA in X.509 (FIPS 204) | Post-quantum signing certificates |
| [RFC 9909](https://www.rfc-editor.org/rfc/rfc9909) | SLH-DSA in X.509 (FIPS 205) | Post-quantum signing certificates |
| [RFC 9935](https://www.rfc-editor.org/rfc/rfc9935) | ML-KEM in X.509 (FIPS 203) | Post-quantum KEM certificates |
| [RFC 9608](https://www.rfc-editor.org/rfc/rfc9608) | No Revocation Available extension | All self-signed end-entity certs |

### Not supported

The following specifications are **not** currently implemented:

- **Merkle Tree Certificates** (IETF draft) — transparency-based certificate format.
- **Composite Certificates** (draft-ietf-lamps-pq-composite-sigs / draft-ietf-lamps-pq-composite-kem) — hybrid classical+PQC keys in a single certificate.
- **OCSP responder** — the KMS does not act as an OCSP responder.
- **CRL generation** — the KMS does not generate CRLs; it can include `crlDistributionPoints` pointing to an external CRL.

## Certificate export formats

Certificates and their associated private keys can be exported in:

- **PEM** (`.pem`) — Base64-encoded, human-readable.
- **DER** (`.der`) — Binary ASN.1 encoding.
- **PKCS#12** (`.p12` / `.pfx`) — Bundled certificate + private key, password-protected.

## Post-quantum algorithms

!!! note "Non-FIPS build required"
    PQC algorithms (ML-DSA, SLH-DSA, ML-KEM) are only available in the **non-FIPS** build
    (`--features non-fips`). The FIPS build restricts algorithms to those approved under
    the FIPS 140-3 boundary.

### Algorithm identifiers (OIDs)

#### ML-DSA — signing (RFC 9881, FIPS 204)

| Variant    | OID                         |
| ---------- | --------------------------- |
| ML-DSA-44  | `2.16.840.1.101.3.4.3.17`   |
| ML-DSA-65  | `2.16.840.1.101.3.4.3.18`   |
| ML-DSA-87  | `2.16.840.1.101.3.4.3.19`   |

#### SLH-DSA — signing (RFC 9909, FIPS 205)

| Variant              | OID                        |
| -------------------- | -------------------------- |
| SLH-DSA-SHA2-128s    | `2.16.840.1.101.3.4.20`    |
| SLH-DSA-SHA2-128f    | `2.16.840.1.101.3.4.21`    |
| SLH-DSA-SHA2-192s    | `2.16.840.1.101.3.4.22`    |
| SLH-DSA-SHA2-192f    | `2.16.840.1.101.3.4.23`    |
| SLH-DSA-SHA2-256s    | `2.16.840.1.101.3.4.24`    |
| SLH-DSA-SHA2-256f    | `2.16.840.1.101.3.4.25`    |
| SLH-DSA-SHAKE-128s   | `2.16.840.1.101.3.4.26`    |
| SLH-DSA-SHAKE-128f   | `2.16.840.1.101.3.4.27`    |
| SLH-DSA-SHAKE-192s   | `2.16.840.1.101.3.4.28`    |
| SLH-DSA-SHAKE-192f   | `2.16.840.1.101.3.4.29`    |
| SLH-DSA-SHAKE-256s   | `2.16.840.1.101.3.4.30`    |
| SLH-DSA-SHAKE-256f   | `2.16.840.1.101.3.4.31`    |

#### ML-KEM — key encapsulation (RFC 9935, FIPS 203)

| Variant     | OID                        |
| ----------- | -------------------------- |
| ML-KEM-512  | `2.16.840.1.101.3.4.4.1`   |
| ML-KEM-768  | `2.16.840.1.101.3.4.4.2`   |
| ML-KEM-1024 | `2.16.840.1.101.3.4.4.3`   |

### Key usage requirements

!!! important "RFC-mandated key usage extensions"
    The Cosmian KMS automatically adds the correct critical `keyUsage` extension
    to every PQC certificate it generates, per the applicable IETF standard.

#### ML-DSA and SLH-DSA (signing algorithms)

Per RFC 9881 §5 and RFC 9909 §6:

- The `keyUsage` extension **MUST** be present and **MUST** be critical.
- It **MUST** include `digitalSignature`.
- For CA certificates: `keyCertSign` and `cRLSign` are added.

```text
X509v3 Key Usage: critical
    Digital Signature
```

#### ML-KEM (key encapsulation algorithm)

Per RFC 9935 §5:

- The `keyUsage` extension **MUST** be present and **MUST** be critical.
- It **MUST** contain `keyEncipherment` and **MUST NOT** contain any other bit.

```text
X509v3 Key Usage: critical
    Key Encipherment
```

!!! note "ML-KEM cannot self-sign"
    ML-KEM is a **key encapsulation mechanism** (KEM), not a signature scheme.
    An ML-KEM key cannot be used to sign its own certificate.
    ML-KEM certificates **must always be CA-issued**: supply
    `--issuer-private-key-id` and `--issuer-certificate-id` pointing to
    a signing key (RSA, EC, ML-DSA, or SLH-DSA).

## Generating certificates with the CLI

### Self-signed ML-DSA-44 certificate

```shell
ckms certificates certify \
  --generate-key-pair \
  --algorithm ml-dsa-44 \
  --subject-name "CN=My ML-DSA CA,O=Acme,C=FR" \
  --days 365
```

The server will:

1. Generate an ML-DSA-44 key pair.
2. Issue a self-signed X.509 v3 certificate.
3. Automatically add a **critical** `keyUsage` extension with `digitalSignature`
   (per RFC 9881).
4. Return the certificate identifier.

### CA-issued ML-KEM-512 certificate (RFC 9935)

First create an ML-DSA-44 CA:

```shell
# Step 1: create the CA certificate (self-signed ML-DSA-44)
CA_CERT_ID=$(ckms certificates certify \
  --generate-key-pair \
  --algorithm ml-dsa-44 \
  --subject-name "CN=PQC Root CA,O=Acme,C=FR" \
  --days 3650 \
  | grep "Certificate ID" | awk '{print $NF}')

# Retrieve the CA private key ID from the certificate attributes
CA_SK_ID=$(ckms certificates export \
  --certificate-id "$CA_CERT_ID" \
  --output-format json-ttlv \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(next(l['LinkedObjectIdentifier'] for l in d.get('Link',[]) if l['LinkType']=='PrivateKeyLink'))")
```

Then issue an ML-KEM-512 leaf certificate signed by the CA:

```shell
# Step 2: create an ML-KEM-512 leaf certificate signed by the CA
ckms certificates certify \
  --generate-key-pair \
  --algorithm ml-kem-512 \
  --subject-name "CN=ML-KEM-512 Leaf,O=Acme,C=FR" \
  --issuer-private-key-id "$CA_SK_ID" \
  --issuer-certificate-id "$CA_CERT_ID" \
  --days 365
```

The server will:

1. Generate an ML-KEM-512 key pair.
2. Issue an X.509 certificate signed by the ML-DSA-44 CA.
3. Automatically add a **critical** `keyUsage` extension with `keyEncipherment`
   only (per RFC 9935).

### SLH-DSA-SHA2-128s self-signed certificate

```shell
ckms certificates certify \
  --generate-key-pair \
  --algorithm slh-dsa-sha2-128s \
  --subject-name "CN=SLH-DSA Test,O=Acme,C=FR" \
  --days 365
```

### RSA or EC self-signed certificate

```shell
# RSA 4096
ckms certificates certify \
  --generate-key-pair \
  --algorithm rsa4096 \
  --subject-name "CN=RSA CA,O=Acme,C=FR" \
  --days 365

# NIST P-256
ckms certificates certify \
  --generate-key-pair \
  --algorithm nist-p256 \
  --subject-name "CN=EC CA,O=Acme,C=FR" \
  --days 365
```

## Verifying certificates with OpenSSL 3.5+

OpenSSL 3.5+ supports all NIST PQC algorithms. Use the following commands to
inspect and verify PQC certificates:

```shell
# Inspect the certificate
openssl x509 -text -noout -in ml-dsa-cert.pem

# Verify a leaf certificate against a CA certificate
openssl verify -CAfile ca-cert.pem leaf-cert.pem
```

## Using the Web UI

The Cosmian KMS Web UI exposes certificate generation through the
**Certificate Issuance and Renewal** page at `/ui/certificates/certs/certify`.

- Select **"4. Generate New Keypair"**.
- Choose an algorithm from the **Key Algorithm** dropdown
  (e.g. `ML-DSA-44 (PQC)`, `ML-KEM-512 (KEM)`, `RSA-4096`, `NIST-P256`).
- Enter a subject name.
- Optionally provide issuer key and certificate IDs for CA-signed certificates.

!!! note
    ML-KEM algorithms appear under **(KEM)** in the dropdown to signal that
    they require a CA issuer. Attempting to create a self-signed ML-KEM
    certificate will return an error.

## Cross-algorithm PKI

RFC 9881 and RFC 9935 explicitly support **cross-algorithm PKI**: the CA signing
key does not need to match the subject key algorithm.

Examples of supported combinations:

| CA algorithm | Leaf/subject algorithm | Use case                              |
| ------------ | ---------------------- | ------------------------------------- |
| ML-DSA-44    | ML-KEM-512             | PQC-only PKI (RFC 9935)               |
| ML-DSA-44    | ML-DSA-65              | Hierarchical PQC signing chain        |
| SLH-DSA-SHA2-128s | ML-DSA-44         | Cross-family PQC PKI                  |
| ML-DSA-44    | RSA 4096               | PQC CA, classical leaf (transition)   |
| RSA 4096     | ML-DSA-44              | Classical CA, PQC leaf (transition)   |

## Certificate lifecycle

All standard KMIP certificate lifecycle operations work with certificates:

| Operation | Description                                             |
| --------- | ------------------------------------------------------- |
| `Certify` | Generate a new certificate (self-signed or CA-issued)   |
| `Export`  | Export in PEM, DER, or PKCS#12 format                   |
| `Import`  | Import an externally generated certificate              |
| `Validate`| Validate a certificate chain                            |
| `Revoke`  | Revoke a certificate                                    |
| `Destroy` | Permanently delete a certificate and its keys           |

## Revocation handling

### CRL distribution points

To include a CRL distribution point in a certificate, add a
`crlDistributionPoints` entry in the extension config file passed via
`--certificate-extensions`:

```ini
[ v3_ext ]
crlDistributionPoints=URI:http://ca.example.com/crl.pem
```

### Authority Information Access (AIA)

The AIA extension (`authorityInfoAccess`, OID 1.3.6.1.5.5.7.1.1) can be added
via the extension config file to point to an OCSP responder or CA issuer:

```ini
[ v3_ext ]
authorityInfoAccess=OCSP;URI:http://ocsp.example.com/,caIssuers;URI:http://ca.example.com/ca.crt
```

### No Revocation Available (`id-ce-noRevAvail`, RFC 9608)

For **self-signed certificates** (no issuer key provided) that do not carry a
CRL distribution point, the KMS automatically adds the
`id-ce-noRevAvail` extension (OID 2.5.29.56, RFC 9608 §2). This signals
to relying parties that no revocation information is available for this
certificate, and that they should not reject it for lack of a CRL or OCSP
response.

This behavior applies to **all algorithms** (RSA, EC, ML-DSA, SLH-DSA, …),
not only PQC.

When validating a chain, the KMS skips CRL fetching for any certificate that
carries this extension.
