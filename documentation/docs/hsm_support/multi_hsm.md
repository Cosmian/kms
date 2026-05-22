# Multi-HSM Support

Cosmian KMS can connect to **multiple Hardware Security Modules simultaneously**.
Each HSM instance is independently initialised via PKCS#11 and exposed to the rest
of the server through a unique *routing prefix* derived from its model name.

---

## Routing prefix scheme

Every KMS object stored inside an HSM has a UID of the form:

```text
hsm::<model>::<slot_id>::<key_id>
```

The model name embedded in the prefix allows the server to route any KMIP operation
to the correct HSM without additional configuration.

| Configuration | Prefix | Example UID |
|---|---|---|
| Single `softhsm2` instance | `hsm::softhsm2` | `hsm::softhsm2::0::my-aes-key` |
| Single `utimaco` instance | `hsm::utimaco` | `hsm::utimaco::0::another-key` |
| First of two `softhsm2` instances | `hsm::softhsm2` | `hsm::softhsm2::0::key-a` |
| Second of two `softhsm2` instances | `hsm::softhsm2_1` | `hsm::softhsm2_1::1::key-b` |
| Third of two `softhsm2` instances | `hsm::softhsm2_2` | `hsm::softhsm2_2::2::key-c` |

When the same model appears more than once, the second instance gets the suffix
`_1`, the third `_2`, and so on (e.g. `hsm::softhsm2`, `hsm::softhsm2_1`,
`hsm::softhsm2_2`).

---

## Configuration

### Option A — flat single-HSM CLI flags (backward compatible)

The existing `--hsm-model`, `--hsm-admin`, `--hsm-slot`, and `--hsm-password`
flags continue to work exactly as before.  They configure **one** HSM instance
whose prefix is `"hsm::<model>"`.

### Option B — TOML `[[hsm_instances]]` array (multi-HSM)

Add one `[[hsm_instances]]` section per HSM in `kms.toml`.  When this section is
present it **takes precedence** over the flat CLI flags.

```toml
# First HSM — prefix "hsm::softhsm2"
[[hsm_instances]]
hsm_model    = "softhsm2"
hsm_admin    = ["tech@example.com"]
hsm_slot     = [0]
hsm_password = ["changeme"]

# Second HSM — prefix "hsm::utimaco"
[[hsm_instances]]
hsm_model    = "utimaco"
hsm_admin    = ["tech@example.com"]
hsm_slot     = [0, 1]
hsm_password = ["slot0pass", "slot1pass"]

# Third HSM — same model as first, disambiguated as "hsm::softhsm2_1"
[[hsm_instances]]
hsm_model    = "softhsm2"
hsm_admin    = ["tech@example.com"]
hsm_slot     = [2]
hsm_password = ["anotherpass"]
```

| Field | Description |
|---|---|
| `hsm_model` | HSM model: `softhsm2`, `utimaco`, `proteccio`, `crypt2pay`, `smartcardhsm`, `other` |
| `hsm_admin` | List of KMS user identities that have admin rights on this HSM |
| `hsm_slot` | PKCS#11 slot indices to open |
| `hsm_password` | Login passwords for the corresponding slots (same order as `hsm_slot`) |

---

## Checking HSM status at runtime

The `GET /hsm/status` endpoint (no authentication required) returns a JSON array
of all configured HSM instances:

```bash
curl http://localhost:9998/hsm/status
```

Example response:

```json
[
  {
    "prefix": "hsm::softhsm2",
    "model": "softhsm2",
    "slots": [
      { "slot_id": 0, "accessible": true }
    ]
  },
  {
    "prefix": "hsm::utimaco",
    "model": "utimaco",
    "slots": [
      { "slot_id": 0, "accessible": true },
      { "slot_id": 1, "accessible": false }
    ]
  }
]
```

The same information is available in the **HSM Status** page of the Web UI
(`Objects → HSM Status`).

---

## Supported platforms

HSM support is available on:

- Linux x86\_64 — all models (`softhsm2`, `utimaco`, `proteccio`, `crypt2pay`, `smartcardhsm`, `other`)
- macOS (arm64 / x86\_64) — `softhsm2` and `smartcardhsm` only

---

## See also

- [SoftHSM2 setup](softhsm2.md)
- [Utimaco setup](utimaco.md)
- [Proteccio setup](proteccio.md)
- [HSM operations](hsm_operations.md)
