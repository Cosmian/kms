# Multi-HSM Support

Cosmian KMS can connect to **multiple Hardware Security Modules simultaneously**.
Each HSM instance is independently initialised via PKCS#11 and exposed to the rest
of the server through a unique *routing prefix*.

---

## Routing prefix scheme

Every KMS object stored inside an HSM has a UID of the form:

```text
hsm::<model>::<slot_id>::<key_id>
```

| HSM model | Prefix | Example UID |
|---|---|---|
| softhsm2 | `hsm::softhsm2` | `hsm::softhsm2::0::my-aes-key` |
| utimaco | `hsm::utimaco` | `hsm::utimaco::0::another-key` |
| proteccio | `hsm::proteccio` | `hsm::proteccio::1::yet-another-key` |
| … | `hsm::<model>` | … |

If two HSM instances use the **same model**, the second one gets a `_1` suffix
(e.g. `hsm::utimaco` and `hsm::utimaco_1`).

The server routes any KMIP operation to the correct HSM by matching the prefix of
the object UID.

---

## Configuration

### Option A — flat single-HSM CLI flags (backward compatible)

The existing `--hsm-model`, `--hsm-admin`, `--hsm-slot`, and `--hsm-password`
flags continue to work exactly as before.  They configure **one** HSM instance
with the prefix `"hsm::<model>"` (derived from the `--hsm-model` value).

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
