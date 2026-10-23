# Delegated sub-CA with an HSM-protected key

An online KMS can host a **delegated (sub) CA** whose private key never leaves the KMS
or its HSM, while the **root CA** stays on a separate, offline KMS. The online KMS
generates a PKCS#10 certificate signing request (CSR) for the sub-CA key; the offline
root signs it.

```mermaid
sequenceDiagram
    participant On as Online KMS (HSM)
    participant Off as Offline root KMS
    On->>On: create sensitive key pair
    On->>On: generate-csr (signed by the HSM key)
    On->>Off: subca.csr (file transfer)
    Off->>Off: certify the CSR with the root key
    Off->>On: sub-CA certificate (file transfer)
    On->>On: import certificate, link it to the key
```

## 1. Create a non-extractable key on the online KMS

For an HSM key, use an `hsm::<slot>::<id>` identifier and `--sensitive`, so the key
cannot be exported from the HSM:

```bash
ckms rsa keys create --sensitive --size_in_bits 4096 hsm::0::subca
```

## 2. Generate the CSR

```bash
ckms certificates generate-csr \
  --private-key-id hsm::0::subca \
  --subject-name "C=FR, O=Acme, CN=Acme Sub CA" \
  --output-file subca.csr
```

The CSR is signed inside the KMS (for an HSM key, by the HSM through PKCS#11); the private key
is never loaded into the server. The caller needs the `Sign` permission on the key, not `Get`.
Web UI: **Certificates > Generate CSR**. REST: `POST /certificates/csr`.

An HSM key that is **extractable** is refused: create it with `--sensitive`.

## 3. Sign the CSR on the offline root

```bash
ckms certificates certify \
  --certificate-signing-request subca.csr \
  --issuer-private-key-id <ROOT_KEY_ID> \
  --issuer-certificate-id <ROOT_CERT_ID> \
  --certificate-extensions subca_ext.cnf
```

with `basicConstraints=critical,CA:TRUE` and `keyUsage=critical,keyCertSign,crlSign` in the
extension file.

## 4. Use the sub-CA

Import the signed certificate on the online KMS and link it to the HSM key
(`PrivateKeyLink`). The sub-CA can then issue certificates (`certify` with the sub-CA as issuer)
and CRLs (`generate-crl`): the signatures are computed by the HSM.

## Limits

- Certificate, CRL and OCSP signing with an HSM-resident issuer key support RSA, EC and (non-FIPS builds)
  Ed25519/Ed448 keys. ML-DSA and SLH-DSA HSM keys are not supported.
- The SCEP enrollment endpoint refuses a non-extractable HSM CA key (clear error, no fallback to an exported key).
  EST works, as it issues through `certify`.
- Automatic CRL regeneration after a revocation reads the issuer certificate directly and authorizes the signing
  key as that certificate's owner: for an `hsm::` key, the owner must be an HSM admin or hold a grant on the key.

## Finding certificates by serial number

Every certificate created or imported now carries a system tag `_serial=<SERIAL_IN_UPPERCASE_HEX>`
(the format of `openssl x509 -noout -serial`), so operators can locate a certificate without
knowing KMIP:

```bash
ckms locate --tag _serial=0A1B2C3D
```
