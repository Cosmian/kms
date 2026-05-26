# E2E Playwright Tests

End-to-end tests validating the UI → WASM → KMIP → KMS pipeline.

## FIPS mode

Run `bash .github/scripts/nix.sh --variant fips test ui` to execute the suite
against a FIPS-mode KMS server. Three spec files are automatically skipped in
FIPS mode because they exercise algorithms that are not NIST-approved:

| Skipped spec      | Reason                                            |
| ----------------- | ------------------------------------------------- |
| `covercrypt-flow` | Covercrypt is a non-FIPS algorithm                |
| `pqc-key-flow`    | ML-KEM, ML-DSA, SLH-DSA are non-FIPS              |
| `pqc-encaps-sign` | ML-KEM, ML-DSA, SLH-DSA, Hybrid KEMs are non-FIPS |

In addition, specific individual tests inside otherwise-FIPS-compatible spec files
are skipped because the underlying algorithm is not FIPS 140-3 approved:

| Spec                 | Test                                             | Reason                                       |
| -------------------- | ------------------------------------------------ | -------------------------------------------- |
| `ec-encrypt-sign`    | ECIES encrypt then decrypt preserves plaintext   | ECIES KDF is not FIPS-approved               |
| `ec-encrypt-sign`    | encrypt with wrong public key then decrypt fails | ECIES KDF is not FIPS-approved               |
| `rsa-export-options` | wrap sym key with RSA PKCS v1.5                  | RSA PKCS1v15 encryption is not FIPS-approved |

These skips are controlled by the `PLAYWRIGHT_FIPS_MODE=true` environment variable,
which `test_ui.sh` injects automatically when run with `--variant fips`.

All remaining specs (symmetric, RSA, EC/P-256 sign/verify, certificates, MAC, locate,
attributes, access-rights, cloud integrations, …) run unchanged in FIPS mode.

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

Covers ECIES encryption and ECDSA signing on NIST P-256.

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

### certificates-certify

_PQC tests skipped in FIPS mode._

Full coverage of all four certification methods and all supported algorithms:

```mermaid
graph LR
    subgraph "Method 4 — Generate New Keypair"
        A1[RSA-2048 / RSA-4096] --> SS1[Self-signed cert]
        A2[P-256 / P-384 / P-521 / Ed25519] --> SS2[Self-signed cert]
        A3[ML-DSA-44/65/87] --> SS3[Self-signed cert]
        A4[SLH-DSA-SHA2-128s/f 192s 256s SHAKE-128s/256s] --> SS4[Self-signed cert]
        A5[ML-KEM-512] --> ERR[Server rejects KEM self-sign]
    end
    subgraph "Method 2 — Certify existing public key"
        B1[Create EC P-256 pair] --> B2[Certify pubKey]
        B3[Create ML-DSA-44 pair] --> B4[Certify pubKey]
    end
    subgraph "Method 3 — Re-certify"
        C1[Create P-256 self-signed] --> C2[Re-certify → new cert ID]
    end
    subgraph "CA-issued"
        D1[Create ML-DSA-44 CA] --> D2[Issue ML-KEM-512 leaf]
        D1 --> D3[Issue ML-KEM-768 leaf]
        D1 --> D4[Issue ML-KEM-1024 leaf]
        D1 --> D5[Issue RSA-4096 leaf cross-algo]
    end
    subgraph "Optional cert ID"
        E1[Provide custom UUID] --> E2[Returned ID matches]
    end
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
    A[Create sym key + RSA pair + EC pair] --> B[Filter by ObjectType]
    B --> C[Filter by algorithm]
    C --> D[Filter by cryptographic length]
    D --> E[Filter by key format type]
    E --> F[Filter by linked object ID]
    F --> G[Combined filters]
    G --> H[Verify table rendering]
```

Covers six groups of locate filters:

- **Basic**: filter by ObjectType (SymmetricKey), by State (Active), by tag
- **Algorithm**: locate by AES, RSA, or ECDH (EC keys stored as ECDH by `build_algorithm_from_curve`)
- **Cryptographic length**: locate by exact bit-length (256, 2048)
- **Key format type**: locate by Raw, PKCS8, etc.
- **Linked object IDs**: locate by private→public key link
- **Combined**: ObjectType + algorithm + length simultaneously
- **Table rendering**: columns (UID, Type, Key Format Type, State, Algorithm, Length) render correctly; UID links navigate to detail pages

### locate-attributes

```mermaid
graph LR
    A[Pre-created HSM keys] --> B[Locate SymmetricKey]
    B --> C{Type = SymmetricKey?}
    C -->|Yes| D[Pass]
    B --> E{Key Format Type = Raw?}
    E -->|Yes| F[Pass]
    G[Create software keys] --> H[Locate each type]
    H --> I{No N/A in Type column?}
    I -->|Yes| J[Pass]
```

Validates that the Locate results table displays correct attribute values for both
HSM and software keys. Specifically:

- HSM keys show `SymmetricKey` type (not `N/A`)
- HSM keys show `Raw` key format type (not `N/A`)
- Software symmetric keys show correct type and format
- RSA private keys show `PrivateKey` type and `PKCS1`/`PKCS8` format
- EC private keys show `PrivateKey` type (format is not `N/A`)
- All located objects have a valid Type value (no `N/A`)

The HSM tests require `PLAYWRIGHT_HSM_KEY_COUNT > 0` (set by `test_ui.sh`).

### locate-hsm

```mermaid
graph LR
    A[Create HSM AES key] --> B[Create software AES key]
    B --> C[Locate by ObjectType]
    C --> D{Both appear?}
    D -->|Yes| E[Pass]
    D -->|No| F[Fail]
    G[3 slots × 3 prefixes] --> H[Locate all]
    H --> I{All 3 found?}
    I -->|Yes| J[Pass]
    K[mTLS user cert] --> L[Locate HSM keys]
    L --> M{0 HSM keys visible?}
    M -->|Yes| N[Pass]
```

Validates that HSM keys (created with the `hsm::` prefix) appear alongside
software keys in Locate results. HSM keys always show `Active` state and no
`Unknown` state is present. The `PLAYWRIGHT_HSM_KEY_COUNT` HSM keys
pre-created by `test_ui.sh` are discovered through table pagination.
The inner `Locate – HSM keys (real SoftHSM2)` suite is skipped automatically
when `PLAYWRIGHT_HSM_KEY_COUNT` is 0 (SoftHSM2 not available).

Additional test groups:

- **Multi-HSM prefix routing**: verifies that pre-created keys from all three
  SoftHSM2 slots appear in Locate results using the three prefix styles:
  `hsm::<slot>::`, `hsm::softhsm2::<slot>::`, and `hsm::softhsm2_1::<slot>::`.
  Skipped when `PLAYWRIGHT_HSM_SLOT_ID_1/2/3` are unset.
- **HSM access control (mTLS)**: connects as a non-admin user (via the user
  mTLS certificate) and asserts that no HSM keys (`hsm::` prefix) are visible —
  only the HSM admin (owner cert) can see them.

### hsm-multi-keys

```mermaid
graph LR
    A[Slot 1: hsm::slot1::name] --> B[Create key]
    B --> C[Destroy key]
    D[Slot 2: hsm::softhsm2::slot2::name] --> E[Create key]
    E --> F[Destroy key]
    G[Slot 3: hsm::softhsm2_1::slot3::name] --> H[Create key]
    H --> I[Destroy key]
    J[All 3 slots] --> K[Create 3 keys]
    K --> L[Destroy 3 keys]
```

Tests end-to-end key creation and destruction for three independent SoftHSM2
instances using both the legacy UID prefix (`hsm::<slot>::<name>`) and the new
model-qualified prefixes (`hsm::softhsm2::<slot>::<name>` and
`hsm::softhsm2_1::<slot>::<name>`). Slot IDs are passed via
`PLAYWRIGHT_HSM_SLOT_ID_1/2/3` environment variables set by `test_ui.sh`.
The suite is skipped automatically when any of the three slot IDs is unset.

### mac-flow

```mermaid
graph LR
    A[Create HMAC key] --> B[Compute MAC]
    B --> C[Verify MAC]
    C --> D{Result}
    D -->|Correct MAC| E[valid]
    D -->|Wrong MAC| F[invalid]
```

Covers HMAC-SHA256 and HMAC-SHA1 (issue #786). Tests include:

- Navigation smoke tests for the compute and verify pages
- HMAC-SHA256 compute returning `MAC (hex): <hex>`
- HMAC-SHA1 compute
- Error when key ID is missing
- Compute → verify roundtrip returning `valid` (SHA256 and SHA1)
- Wrong MAC → `invalid`

## CoverCrypt

_Skipped in FIPS mode._

### covercrypt-flow

```mermaid
graph LR
    A[Create master pair] --> B[Create user decryption key]
    B --> C[Export keys]
    C --> D[Revoke]
    D --> E[Destroy]
```

## Post-Quantum Cryptography (PQC)

_Skipped in FIPS mode._

### pqc-key-flow

```mermaid
graph LR
    A[Create ML-KEM-512 pair] --> B[Create ML-DSA-65 pair]
    B --> C[Export private key JSON-TTLV]
    C --> D[Revoke ML-KEM-768 key]
    D --> E[Destroy]
    A --> F[Navigate import/encap/decap/sign/verify pages]
```

Covers ML-KEM-512, ML-KEM-768 and ML-DSA-65 key-pair creation, export, revoke,
destroy, and navigation to all PQC operation pages.

### pqc-encaps-sign

```mermaid
graph LR
    A[Create ML-KEM-512 pair] --> B[Encapsulate]
    B --> C[Decapsulate]
    C --> D{Shared secrets match?}
    D -->|Yes| E[Pass]

    F[Create ML-DSA pair] --> G[Sign]
    G --> H[Verify]
    H --> I{Valid / Invalid}
```

Covers:

- ML-KEM-512 encapsulate → decapsulate roundtrip
- Encapsulate without key ID → error
- ML-DSA-44/65/87 sign → verify (correct key → `Valid`; wrong key → `invalid`; tampered data → `invalid`)
- Hybrid KEM X25519MLKEM768 encapsulate → decapsulate
- SLH-DSA-SHA2-128s sign → verify (signatures > 1 000 bytes)
- Configurable hybrid KEMs (ML-KEM-512-P256, ML-KEM-768-P256, ML-KEM-512-Curve25519, ML-KEM-768-Curve25519) key creation with mocked `branding.json`

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

### aws-flow

Navigation / smoke tests for AWS BYOK pages. Functional tests require external
AWS KEK files and are therefore kept as navigation-only checks.

```mermaid
graph LR
    A[Navigate AWS import-kek] --> B[Verify page renders]
    C[Navigate AWS export-key-material] --> D[Verify page renders]
```

## Derive Key

### derive-key-flow

```mermaid
graph LR
    A[Create AES-256 key with DeriveKey mask] --> B[Navigate /derive-key]
    B --> C[PBKDF2 derive → check UUID in response]
    A --> D[PBKDF2 with custom output key ID]
    A --> E[HKDF derive → check UUID in response]
```

Tests create the base key directly via the KMIP API (with `CryptographicUsageMask:
DeriveKey = 0x200`) because the standard key-creation UI form does not expose
that mask. All three derivation paths (basic PBKDF2, PBKDF2 with custom output ID,
and HKDF) are exercised.

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
    C --> D[Modify attribute]
    D --> E[Delete attribute]
```

Covers:

- Navigation to get/set/modify/delete attribute pages
- `child_id` link: set+delete; set+modify
- Name attribute (KMIP standard, issue #746): set; set → get (not hex); set → modify → delete
- `cryptographic_length`: set → get → modify
- `key_usage`: set → delete
- `cryptographic_algorithm`: set
- Multiple link attributes on one key
- Non-existent object ID returns response (no crash)

### vendor-id-flow

```mermaid
graph LR
    A[Query server info] --> B[Extract vendor ID]
    B --> C[Verify KMIP requests use vendor ID]
```

### auth-connection-states

Tests the five UI connection states introduced in the auth overhaul:

```mermaid
graph LR
    A[Load UI] --> B{VITE_DEV_MODE?}
    B -->|true| C[DEV banner visible]
    B -->|false + no auth| D[No-auth warning banner]
    B -->|false + no server| E[Cannot connect error page]
    A --> F["/login while authenticated, redirects to /locate"]
    A --> G["/ index redirects to /locate"]
    A --> H[Footer shows version + health]
```

Note: the "Cannot connect to KMS server" state (`authMethod === undefined`) requires
a UI built without `VITE_DEV_MODE=true`; it is covered by unit tests instead.

### sitemap

```mermaid
graph LR
    A[For each route] --> B[Navigate]
    B --> C[Verify page loads]
```
