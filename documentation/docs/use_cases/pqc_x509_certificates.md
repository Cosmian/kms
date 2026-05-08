# Post-Quantum X.509 Certificates

The Cosmian KMS supports generating, storing, and managing **post-quantum X.509 certificates**
for all NIST-standardized PQC algorithms: **ML-DSA** (CRYSTALS-Dilithium), **SLH-DSA** (SPHINCS+),
and **ML-KEM** (CRYSTALS-Kyber).

## Standards references

| Algorithm family | X.509 standard  | NIST standard   | Key usage                                      |
| ---------------- | --------------- | --------------- | ---------------------------------------------- |
| ML-DSA           | RFC 9881        | FIPS 204        | `digitalSignature` (critical)                  |
| SLH-DSA          | draft-ietf-lamps-x509-slh-dsa | FIPS 205 | `digitalSignature` (critical)         |
| ML-KEM           | RFC 9935        | FIPS 203        | `keyEncipherment` only (critical)              |

These algorithms are **quantum-resistant**: they remain secure even against adversaries equipped
with large-scale quantum computers.

## Algorithm identifiers (OIDs)

### ML-DSA — signing (RFC 9881)

| Variant    | OID                         |
| ---------- | --------------------------- |
| ML-DSA-44  | `2.16.840.1.101.3.4.3.17`   |
| ML-DSA-65  | `2.16.840.1.101.3.4.3.18`   |
| ML-DSA-87  | `2.16.840.1.101.3.4.3.19`   |

### SLH-DSA — signing (draft-ietf-lamps-x509-slh-dsa)

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

### ML-KEM — key encapsulation (RFC 9935)

| Variant     | OID                        |
| ----------- | -------------------------- |
| ML-KEM-512  | `2.16.840.1.101.3.4.4.1`   |
| ML-KEM-768  | `2.16.840.1.101.3.4.4.2`   |
| ML-KEM-1024 | `2.16.840.1.101.3.4.4.3`   |

## Key usage requirements

!!! important "RFC-mandated key usage extensions"
    The Cosmian KMS automatically adds the correct critical `keyUsage` extension
    to every PQC certificate it generates, per the applicable IETF standard.

### ML-DSA and SLH-DSA (signing algorithms)

Per RFC 9881 §4 and draft-ietf-lamps-x509-slh-dsa §4:

- The `keyUsage` extension **MUST** be present and **MUST** be critical.
- It **MUST** include `digitalSignature`.

```text
X509v3 Key Usage: critical
    Digital Signature
```

### ML-KEM (key encapsulation algorithm)

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
    ML-KEM certificates **must always be CA-issued**: you must supply
    `--issuer-private-key-id` and `--issuer-certificate-id` pointing to
    a signing key (RSA, EC, ML-DSA, or SLH-DSA).

## Generating PQC certificates with the CLI

> **Note**: PQC algorithms are only available in the **non-FIPS** build.
> Run the server and CLI with `--features non-fips`.

### 1. Self-signed ML-DSA-44 certificate

Generate a self-signed X.509 certificate using an ML-DSA-44 key pair:

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

### 2. CA-issued ML-KEM-512 certificate (RFC 9935)

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

### 3. SLH-DSA-SHA2-128s self-signed certificate

```shell
ckms certificates certify \
  --generate-key-pair \
  --algorithm slh-dsa-sha2-128s \
  --subject-name "CN=SLH-DSA Test,O=Acme,C=FR" \
  --days 365
```

## Verifying a PQC certificate with OpenSSL 3.5+

OpenSSL 3.5+ supports all NIST PQC algorithms. Use the following commands to
inspect and verify PQC certificates:

```shell
# Inspect the certificate
openssl x509 -text -noout -in ml-dsa-cert.pem

# Verify a leaf certificate against a CA certificate
openssl verify -CAfile ca-cert.pem leaf-cert.pem
```

Expected output for ML-DSA-44:

```text
Certificate:
    Data:
        ...
        Public Key Algorithm: ML-DSA-44
        ...
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
```

Expected output for ML-KEM-512:

```text
Certificate:
    Data:
        ...
        Public Key Algorithm: ML-KEM-512
        ...
        X509v3 extensions:
            X509v3 Key Usage: critical
                Key Encipherment
```

## Using the Web UI

The Cosmian KMS Web UI exposes PQC certificate generation through the
**Certificate Issuance and Renewal** page at `/ui/certificates/certs/certify`.

- Select **"4. Generate New Keypair"**.
- Choose one of the PQC algorithms from the **Key Algorithm** dropdown
  (e.g. `ML-DSA-44 (PQC)`, `ML-KEM-512 (KEM)`).
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

All standard KMIP certificate lifecycle operations work with PQC certificates:

| Operation | Description                                             |
| --------- | ------------------------------------------------------- |
| `Certify` | Generate a new PQC certificate (see above)              |
| `Export`  | Export in PEM, DER, or PKCS#12 format                   |
| `Import`  | Import an externally generated PQC certificate          |
| `Validate`| Validate a PQC certificate chain                        |
| `Revoke`  | Revoke a PQC certificate                                |
| `Destroy` | Permanently delete a PQC certificate and its keys       |

## Technical notes

### Digest algorithm selection

The digest used for signing is determined by the **issuer's** signing key type,
not the subject key:

- **RSA / ECDSA issuers**: use SHA-256 as the external digest.
- **ML-DSA / SLH-DSA / EdDSA issuers**: these algorithms handle their digest
  internally; the KMS passes a null digest to OpenSSL so the algorithm
  computes its own hash. This is the correct behavior per FIPS 204 and FIPS 205.

### X.509 version

All generated PQC certificates are **X.509 version 3**, as required by RFC 5280.

### Key format

ML-DSA and SLH-DSA keys are stored in **PKCS#8** (`SubjectPublicKeyInfo`) format.
ML-KEM keys are stored in **PKCS#8** format; OpenSSL 3.4+ can encode them as
`SubjectPublicKeyInfo` DER, making them embeddable in X.509 certificates.

Hybrid KEM algorithms (X25519/ML-KEM-768, X448/ML-KEM-1024, etc.) use a
**Raw** or **ConfigurableKEMPublicKey** format that OpenSSL 3.6 cannot yet
encode as SPKI, and therefore cannot currently be embedded in X.509 certificates.

### Serial number derivation

The serial number is derived from the SHA-1 hash of the subject public key DER
(SubjectPublicKeyInfo), truncated to 20 bytes with the high bit cleared to ensure
a positive ASN.1 integer encoding (per RFC 5280 §4.1.2.2).
