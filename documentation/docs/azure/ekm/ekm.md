
Cosmian KMS implements the Azure External Key Manager (EKM) Proxy API, enabling it to serve as an external key management service for an Azure Managed HSM.

This integration allows organizations to maintain complete physical control over their encryption keys outside of Azure infrastructure while seamlessly integrating with Azure services that support Customer Managed Keys (CMK).

The Cosmian KMS implementation follows and implements the Microsoft EKM Proxy API Specification for v0.1-preview.

## Table of content
<!-- TOC -->
- [Table of content](#table-of-content)
- [Architecture Overview](#architecture-overview)
- [Api specification](#api-specification)
- [Getting started](#getting-started)
  - [Azure Managed HSM Setup](#azure-managed-hsm-setup)
  - [Cosmian KMS setup](#cosmian-kms-setup)
    - [TLS Configuration](#tls-configuration)
    - [Azure EKM Configuration](#azure-ekm-configuration)
- [Testing the integration](#testing-the-integration)
<!-- TOC -->

## Architecture Overview

![high level arch](high_level_arch.png)

![Workflow](sequence.svg)

<!--
TODO(review): please confirm this is correct
Keep this comment in case you need to redraw or edit the diagram in the future

sequenceDiagram
    participant Azure as Azure Service -<br/>(must support CMK)
    participant MHSM as Azure Managed HSM
    participant KMS as Cosmian KMS
    
    Note over Azure: Has encrypted data<br/>protected by DEK
    Note over Azure: DEK needs to be<br/>wrapped/unwrapped
    
    Azure->>MHSM: Encrypt/Decrypt data<br/>using External Key "mykey"
    
    MHSM->>KMS: POST /mykey/wrapkey<br/>{"value": "DEK_plaintext"}
    Note over KMS: KEK NEVER leaves here!<br/>Wrapping happens locally
    KMS->>MHSM: {"value": "DEK_wrapped"}
    
    MHSM->>Azure: Here's your wrapped DEK
    
    Note over Azure: Stores wrapped DEK
-->

## Api specification

All requests and responses for Azure EKM APIs are sent as JSON objects over HTTPS. Each request includes context information to associate Azure Managed HSM logs and audits with Cosmian KMS logs.

The URI format for EKM Proxy API calls is:

```
https://{server}/azureekm/[path-prefix]/{api-specific-paths}?api-version={client-api-version}
```

**Path Prefix:**
- Maximum 64 characters
- Allowed characters: letters (a-z, A-Z), numbers (0-9), slashes (/), and dashes (-)

**External Key ID:**
- Referenced as `{key-name}` in the endpoints below
- Maximum 64 characters
- Allowed characters: letters (a-z, A-Z), numbers (0-9), and dashes (-)


| Endpoint         | Method | Path                                             | Description                                       |
| ---------------- | ------ | ------------------------------------------------ | ------------------------------------------------- |
| Get Proxy Info   | POST   | /azureekm/[path-prefix]/info                     | Health check and proxy details                    |
| Get Key Metadata | POST   | /azureekm/[path-prefix]/{key-name}/metadata      | Retrieve key type, size, and supported operations |
| Wrap Key         | POST   | /azureekm/[path-prefix]/{key-name}/wrapkey       | Wrap (encrypt) a DEK with a KEK                   |
| Unwrap Key       | POST   | /azureekm/[path-prefix]/{key-name}/unwrapkey     | Unwrap (decrypt) a previously wrapped DEK         |

| Algorithm    | Key Type | Description                          |
| ------------ | -------- | ------------------------------------ |
| A256KW       | AES-256  | AES Key Wrap (RFC 3394)              |
| A256KWP      | AES-256  | AES Key Wrap with Padding (RFC 5649) |
| RSA-OAEP-256 | RSA      | RSA-OAEP using SHA-256 and MGF1      |

## Getting started

### Azure Managed HSM Setup

You must have an Azure Managed HSM Pool already created and activated in your Azure subscription. Refer to the [Azure Managed HSM documentation](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/) for setup instructions.

Once the configuration is done, you will need the root CA certificate that the Azure Managed HSM uses for client authentication. This certificate will be configured in Cosmian KMS to validate incoming mTLS connections.

Save this as **`mhsm-root-ca.pem`** - We will need it in the next step.

// TODO more info here

### Cosmian KMS setup

Follow the [Cosmian KMS installation guide](../../installation/installation_getting_started.md) to install the KMS server on your infrastructure. Alternatively, you can deploy a pre-configured VM using the [this page](../../installation/marketplace_guide.md).

The KMS server typically uses the configuration file located at `/etc/cosmian/kms.toml` when installed manually with default parameters. For confidential VMs, the KMS configuration file is located in the encrypted LUKS container at `/var/lib/cosmian_vm/data/app.conf`.

**Important:** The Azure EKM feature requires running Cosmian KMS in non-FIPS mode.

#### TLS Configuration
Configure mutual TLS authentication to accept connections from Azure Managed HSM:

```toml
[tls]
# Your server certificate and private key (PKCS#12 format)
tls_p12_file = "/etc/cosmian/server-cert.p12"
tls_p12_password = "your-secure-password"

# The certificate downloaded in the previous section
# This validates the client certificate presented by Azure MHSM
clients_ca_cert_file = "/etc/cosmian/mhsm-root-ca.pem"
```

To convert PEM certificate and key files to PKCS#12 format using `openssl`:

```bash
openssl pkcs12 -export \
  -in server.crt \
  -inkey server.key \
  -out server-cert.p12 \
  -name "cosmian-kms-server" \
  -passout pass:your-secure-password
```

#### Azure EKM Configuration

```toml
[azure_ekm_config]
# Enable Azure EKM endpoints
azure_ekm_enable = true

# Optional: Path prefix for multi-tenant isolation (max 64 chars: a-z, A-Z, 0-9, /, -)
azure_ekm_path_prefix = "cosmian0"

# The fields below will be reported in the /info endpoint, edit according to your needs
azure_ekm_proxy_vendor = "Cosmian"
azure_ekm_proxy_name = "EKM Proxy Service v0.1-preview"
azure_ekm_ekm_vendor = "Cosmian"
azure_ekm_ekm_product = "Cosmian KMS"

# WARNING: Only set to true for testing! Never in production.
azure_ekm_disable_client_auth = false
```

## Testing the integration

For testing purposes or for debugging, you temporarily disable client authentication:

```toml
[tls]
# Comment this field to disable client auth and allow upcoming requests from anyone
# clients_ca_cert_file = "/etc/cosmian/mhsm-root-ca.pem"

[azure_ekm_config]
# change to false
azure_ekm_disable_client_auth = false

```

Restart the KMS server:

```bash
sudo systemctl restart cosmian-kms
```

Test the `/info` endpoint:

```bash
curl -X POST "https://ekm.yourdomain.com/azureekm/cosmian0/info?api-version=0.1-preview" \
  -H "Content-Type: application/json" \
  -d '{
    "request_context": {
      "request_id": "test-request-123",
      "correlation_id": "test-correlation-456",
      "pool_name": "test-pool"
    }
  }'

```

Expected response (if you used the config above):

```json
{
  "api_version": "0.1-preview",
  "proxy_vendor": "Cosmian",
  "proxy_name": "EKM Proxy Service v=0.1-preview",
  "ekm_vendor": "Cosmian",
  "ekm_product": "Cosmian KMS v5.15.0"
}
```
