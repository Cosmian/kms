# UI Routes & Action Modules Reference

## Contents

- [UI routes](#ui-routes)
- [Action modules](#action-modules)
- [Testing with Chrome DevTools MCP](#testing-with-chrome-devtools-mcp)

---

## UI routes

React SPA client-side routes under `/ui/` (defined in `ui/src/App.tsx`):

| Route                    | Feature                                                | Non-FIPS only     |
| ------------------------ | ------------------------------------------------------ | ----------------- |
| `/ui/locate`             | Object search and listing                              | No                |
| `/ui/sym/*`              | Symmetric key operations                               | No                |
| `/ui/rsa/*`              | RSA key operations                                     | No                |
| `/ui/ec/*`               | EC key operations                                      | No                |
| `/ui/certificates/*`     | Certificate lifecycle                                  | No                |
| `/ui/mac/*`              | MAC compute/verify                                     | No                |
| `/ui/rotation-policy/*`  | Key rotation policies (`sym`, `rsa`, `ec`, `pqc`)      | `pqc` sub-routes  |
| `/ui/derive-key`         | Key derivation                                         | No                |
| `/ui/attributes/*`       | Object attributes management                           | No                |
| `/ui/access-rights/*`    | Access control & Crypto Officer role                   | No                |
| `/ui/hsm-status`         | HSM instance and slot status                           | No                |
| `/ui/kv-secrets`         | Vault KV v2 secrets store                              | No                |
| `/ui/secret-data/*`      | Secret/sensitive data                                  | No                |
| `/ui/opaque-object/*`    | Opaque objects                                         | No                |
| `/ui/aws/*`              | AWS BYOK                                               | No                |
| `/ui/azure/*`            | Azure BYOK                                             | No                |
| `/ui/google-cse`         | Google CSE                                             | No                |
| `/ui/cc/*`               | Covercrypt                                             | Yes               |
| `/ui/fpe/*`              | Format Preserving Encryption                           | Yes               |
| `/ui/pgp/*`              | OpenPGP key & crypto operations                        | Yes               |
| `/ui/pqc/*`              | Post-Quantum Crypto                                    | Yes               |
| `/ui/tokenize/*`         | Tokenization / anonymization operations                | Yes               |
| `/ui/login`              | Login page                                             | No                |

---

## Action modules

Each module in `ui/src/actions/` maps to a group of forms:

| Module            | Forms                                                                                   | Description                         |
| ----------------- | --------------------------------------------------------------------------------------- | ----------------------------------- |
| `Access/`         | Grant, List, Obtained, Revoke, CryptoOfficerRole                                        | Access control & Crypto Officer     |
| `Attributes/`     | Delete, Get, Modify, Set                                                                | Object attribute CRUD               |
| `Certificates/`   | Certify, ReCertify, Decrypt, Encrypt, Export, Import, Validate, GenerateCrl, GenerateCsr | Certificate lifecycle              |
| `CloudProviders/` | AWS export/import, Azure export/import                                                  | Cloud BYOK integrations             |
| `Covercrypt/`     | Encrypt, Decrypt, MasterKey, UserKey                                                    | Functional encryption (`non-fips`)  |
| `EC/`             | KeysCreate, Encrypt, Decrypt, Sign, Verify                                              | Elliptic Curve ops                  |
| `FPE/`            | KeysCreate, Encrypt, Decrypt                                                            | Format Preserving Encryption (`non-fips`) |
| `Keys/`           | CseInfo, DeriveKey, Export, Import, SplitKey, JoinSplitKey, SymKeysCreate               | General & split key operations      |
| `MAC/`            | Compute, Verify                                                                         | Message Authentication Code         |
| `Objects/`        | Activate, Destroy, HsmStatus, Owned, ReKey, Revoke, OpaqueObject, SecretDataCreate      | Object lifecycle & HSM status       |
| `PQC/`            | KeysCreate, Encapsulate, Decapsulate, Sign, Verify                                      | Post-Quantum ops (`non-fips`)       |
| `Pgp/`            | KeysCreate, Encrypt, Decrypt, Sign, Verify                                              | OpenPGP operations (`non-fips`)     |
| `RSA/`            | KeysCreate, Encrypt, Decrypt, Sign, Verify                                              | RSA operations                      |
| `RotationPolicy/` | GetRotationPolicy, SetRotationPolicy                                                    | Automatic key rotation policies     |
| `Secrets/`        | KvSecrets                                                                               | Vault KV v2 secrets management      |
| `Symmetric/`      | Encrypt, Decrypt, Hash                                                                  | Symmetric encryption & hashing      |
| `Tokenize/`       | Hash, Noise, WordMask, WordTokenize, WordPatternMask, AggregateNumber, AggregateDate, ScaleNumber | Data anonymization (`non-fips`) |

---

## Testing with Chrome DevTools MCP

Install: `npx -y chrome-devtools-mcp@latest`

MCP server name in VS Code: `io.github.ChromeDevTools`

Useful tools (fully qualified):

| Tool | Purpose |
| ---- | ------- |
| `io.github.ChromeDevTools:navigate_page` | Navigate to a UI route |
| `io.github.ChromeDevTools:click` | Click a button or element |
| `io.github.ChromeDevTools:fill` | Fill a text input |
| `io.github.ChromeDevTools:fill_form` | Fill multiple form fields at once |
| `io.github.ChromeDevTools:take_screenshot` | Capture the current state |
| `io.github.ChromeDevTools:wait_for` | Wait for an element or condition |
| `io.github.ChromeDevTools:evaluate_script` | Run JS in the page |
| `io.github.ChromeDevTools:list_console_messages` | Check browser console for errors |

**Interaction conventions:**

- Ant Design `<Select>` portals into `document.body` — click the trigger, then click the option in the popup.
- Form submissions trigger WASM → KMIP → server roundtrip. Use `io.github.ChromeDevTools:wait_for` before reading the response panel.
- Target elements by `data-testid` attribute.
