# UI Routes & Action Modules Reference

## Contents

- [UI routes](#ui-routes)
- [Action modules](#action-modules)
- [Testing with Chrome DevTools MCP](#testing-with-chrome-devtools-mcp)

---

## UI routes

React SPA client-side routes under `/ui/`:

| Route                 | Feature                      | Non-FIPS only |
| --------------------- | ---------------------------- | ------------- |
| `/ui/locate`          | Object search and listing    | No            |
| `/ui/sym/*`           | Symmetric key operations     | No            |
| `/ui/rsa/*`           | RSA key operations           | No            |
| `/ui/ec/*`            | EC key operations            | No            |
| `/ui/certificates/*`  | Certificate lifecycle        | No            |
| `/ui/mac/*`           | MAC compute/verify           | No            |
| `/ui/derive-key/*`    | Key derivation               | No            |
| `/ui/attributes/*`    | Object attributes management | No            |
| `/ui/access-rights/*` | Access control               | No            |
| `/ui/secret-data/*`   | Secret/sensitive data        | No            |
| `/ui/opaque-object/*` | Opaque objects               | No            |
| `/ui/aws/*`           | AWS BYOK                     | No            |
| `/ui/azure/*`         | Azure BYOK                   | No            |
| `/ui/google-cse/*`    | Google CSE                   | No            |
| `/ui/cc/*`            | Covercrypt                   | Yes           |
| `/ui/pqc/*`           | Post-Quantum Crypto          | Yes           |
| `/ui/tokenize/*`      | Tokenization operations      | Yes           |
| `/ui/login`           | Login page                   | No            |

---

## Action modules

Each module in `ui/src/actions/` maps to a group of forms:

| Module            | Forms                                                   | Description                  |
| ----------------- | ------------------------------------------------------- | ---------------------------- |
| `Access/`         | Grant, List, Obtained, Revoke                           | Access control management    |
| `Attributes/`     | Delete, Get, Modify, Set                                | Object attribute CRUD        |
| `Certificates/`   | Certify, Decrypt, Encrypt, Export, Import, Validate     | Certificate lifecycle        |
| `CloudProviders/` | AWS export/import, Azure export/import, Google CMEK/CSE | Cloud integrations           |
| `Covercrypt/`     | Encrypt, Decrypt, MasterKey, UserKey                    | Functional encryption        |
| `EC/`             | CreateKeyPair, Encrypt, Decrypt, Sign, Verify           | Elliptic Curve ops           |
| `FPE/`            | KeysCreate, Encrypt, Decrypt                            | Format Preserving Encryption |
| `Keys/`           | CseInfo, DeriveKey, Export, Import, SymKeyCreate        | General key operations       |
| `MAC/`            | Compute, Verify                                         | Message Authentication Code  |
| `Objects/`        | Destroy, ListOwned, Revoke, OpaqueObject, SecretData    | Object lifecycle             |
| `PQC/`            | Encapsulate, Decapsulate, Sign, Verify                  | Post-Quantum ops             |
| `RSA/`            | CreateKeyPair, Encrypt, Decrypt, Sign, Verify           | RSA operations               |
| `Symmetric/`      | Encrypt, Decrypt, Hash                                  | Symmetric encryption         |
| `Tokenize/`       | Hash, Noise, WordMask, PatternMask, Aggregate           | Data anonymization           |

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
