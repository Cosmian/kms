# FortiGate / FortiOS — External KMS via KMIP

Fortinet FortiGate appliances running FortiOS 7.4+ support delegating cryptographic
key storage to an external KMIP-compliant Key Management Server.  Connecting
FortiOS to Cosmian KMS lets network appliances retrieve their encryption keys from
a centrally audited, optionally HSM-backed key store.

---

## Overview

| Item | Details |
|------|---------|
| **Protocol** | KMIP 1.0–1.4 over TCP/TLS |
| **Port** | 5696 (IANA-registered KMIP port) |
| **FortiOS version** | FortiOS 7.4 and above (tested on FortiOS 7.6.0 / FortiGate 40F) |
| **Cosmian KMS feature** | Works with both FIPS and non-FIPS builds |

### KMIP operations used by FortiOS

| KMIP Operation | Purpose |
|---------------|---------|
| `Create` | Create a symmetric key |
| `Locate` | Find an existing key by name using `TemplateAttribute` filter |
| `Get` | Retrieve key material |
| `Activate` | Transition the key to *Active* state |
| `Destroy` | Delete a key on removal or rotation |

!!! note "KMIP 1.0/1.4 compatibility in Cosmian KMS"
    FortiOS uses an older KMIP 1.x encoding that required specific server-side
    fixes, included as of Cosmian KMS 5.22.0:

    - **`Authentication` wrapper (bug fix)**: FortiOS wraps its credentials using
      the full `Authentication { Credential { CredentialType, CredentialValue } }`
      nesting required by the KMIP 1.0 specification.  Earlier server versions
      looked for `CredentialType` as a direct child of `Authentication` and failed
      with `missing field 'CredentialType'`.  The TTLV deserializer now handles
      the correct nesting for all KMIP 1.x clients.

    - **`Locate` name filter via `TemplateAttribute` (bug fix)**: FortiOS
      wraps `Attribute` items inside a `TemplateAttribute` structure in the
      `Locate` request payload.  Without the matching `template_attribute` field
      on the KMIP 1.4 `Locate` type, the server silently discarded the name
      filter, causing every `Locate` to match all objects and
      `MaximumItems=1` to always return the same first key regardless of the
      requested name.  The server now correctly reads `TemplateAttribute`-wrapped
      filters from KMIP 1.0/1.1 clients.

---

## Configuration

### 1. Enable the KMIP socket server

Add a `[socket_server]` section to your `kms.toml`:

```toml
[socket_server]
port = 5696
# TLS is required; FortiOS verifies the server certificate
tls_cert_file = "/etc/kms/server.crt"
tls_key_file  = "/etc/kms/server.key"
# Optional: require client certificates
# tls_ca_file = "/etc/kms/ca.crt"
```

See [Enabling TLS](../configuration/tls.md) and
[Configuration file reference](../configuration/server_configuration_file.md) for
full details.

### 2. Configure FortiOS

In the FortiGate web UI (or via CLI):

```text
config system kmip
    set status enable
    set server-ip   <KMS server IP>
    set server-port 5696
    set ca-cert     <path to KMS CA certificate>
end
```

Refer to the [Fortinet KMIP documentation](https://docs.fortinet.com) for your
FortiOS version to complete key-encryption policy assignment.

---

## Related resources

- [KMIP support summary](../kmip_support/support.md)
- [Enabling TLS on the socket server](../configuration/tls.md)
- [HSM-backed key wrapping](../hsm_support/introduction/index.md)
