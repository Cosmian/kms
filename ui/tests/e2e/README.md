# E2E Playwright Tests

End-to-end tests validating the UI → WASM → KMIP → KMS pipeline.

## Symmetric Keys

### sym-key-flow

```mermaid
graph LR
    A[Create AES key] --> B[Export PKCS8/Raw/JWK]
    B --> C[Import key]
    C --> D[Revoke]
    D --> E[Destroy]
```

### symmetric-encrypt-decrypt

```mermaid
graph LR
    A[Create AES-256 key] --> B[Encrypt plaintext]
    B --> C[Decrypt ciphertext]
    C --> D{Compare}
    D -->|Match| E[Pass]
```

Covers AES-GCM 128/256, nonce sizes, and authenticated data.

## RSA Keys

### rsa-key-flow

```mermaid
graph LR
    A[Create RSA 2048] --> B[Export PKCS1/PKCS8/JWK]
    B --> C[Revoke]
    C --> D[Destroy]
```

### rsa-encrypt-sign

```mermaid
graph LR
    A[Create RSA 2048] --> B[Encrypt with pubKey]
    B --> C[Decrypt with privKey]
    C --> D{Compare}
    A --> E[Sign with privKey]
    E --> F[Verify with pubKey]
    F --> G{Valid?}
```

Covers OAEP-SHA256, CKM-RSA-PKCS, PKCS1v15-SHA256.

### rsa-import-options

```mermaid
graph LR
    A[Import PEM] --> B[Import PKCS8-DER]
    B --> C[Import JWK]
    C --> D[Verify usages & tags]
```

### rsa-export-options

```mermaid
graph LR
    A[Create RSA pair] --> B[Export PKCS1/PKCS8/JWK]
    B --> C[Export wrapped RFC5649/SHA1/SHA256]
    C --> D[Verify formats]
```

## Elliptic Curve Keys

### ec-key-flow

```mermaid
graph LR
    A[Create P-256 pair] --> B[Export PKCS8/SEC1/JWK]
    B --> C[Revoke]
    C --> D[Destroy]
```

### ec-encrypt-sign

```mermaid
graph LR
    A[Create P-256 pair] --> B[Encrypt with pubKey]
    B --> C[Decrypt with privKey]
    C --> D{Compare}
    A --> E[Sign ECDSA-SHA256]
    E --> F[Verify with pubKey]
    F --> G{Valid?}
```

Covers ECIES encryption and ECDSA signing on P-256/P-384/P-521 and Ed25519.

## Certificates

### certificates-flow

```mermaid
graph LR
    A[Navigate Certify] --> B[Navigate Validate]
    B --> C[Navigate Import]
    C --> D[Navigate Export]
    D --> E[Navigate Revoke]
    E --> F[Navigate Destroy]
```

### cert-lifecycle

```mermaid
graph LR
    A[Create RSA pair] --> B[Certify pubKey]
    B --> C[Validate certificate]
    C --> D[Encrypt with cert]
    D --> E[Decrypt with privKey]
    E --> F{Compare}
```

## Locate & Filters

### locate-flow

```mermaid
graph LR
    A[Navigate Locate] --> B[Search]
    B --> C[View results table]
```

### locate-filters

```mermaid
graph LR
    A[Create sym key + RSA pair] --> B[Filter by SymmetricKey type]
    B --> C[Filter by Active state]
    C --> D[Filter by tag]
    D --> E[Verify result counts]
```

## CoverCrypt

### covercrypt-flow

```mermaid
graph LR
    A[Create master pair] --> B[Create user decryption key]
    B --> C[Export keys]
    C --> D[Revoke]
    D --> E[Destroy]
```

## Cloud Integrations

### google-cmek-wrap-flow

```mermaid
graph LR
    A[Create AES key] --> B[Import RSA wrapping key]
    B --> C[Export wrapped key]
    C --> D[Verify 552 bytes]
```

### google-cse-flow

```mermaid
graph LR
    A[Navigate CSE page] --> B[Verify info displayed]
```

### azure-flow

```mermaid
graph LR
    A[Create RSA 2048] --> B[Navigate BYOK export]
    B --> C[Verify wrapping options]
```

## Other Flows

### opaque-flow

```mermaid
graph LR
    A[Create opaque object] --> B[Export]
    B --> C[Import]
    C --> D[Revoke]
    D --> E[Destroy]
```

### secret-data-flow

```mermaid
graph LR
    A[Create secret data] --> B[Export]
    B --> C[Import]
    C --> D[Revoke]
    D --> E[Destroy]
```

### access-rights-flow

```mermaid
graph LR
    A[Create key] --> B[Grant access]
    B --> C[List access rights]
    C --> D[Revoke access]
```

### attributes-flow

```mermaid
graph LR
    A[Create key] --> B[Get attributes]
    B --> C[Set attribute]
    C --> D[Delete attribute]
```

### vendor-id-flow

```mermaid
graph LR
    A[Query server info] --> B[Extract vendor ID]
    B --> C[Verify KMIP requests use vendor ID]
```

### sitemap

```mermaid
graph LR
    A[For each route] --> B[Navigate]
    B --> C[Verify page loads]
```
