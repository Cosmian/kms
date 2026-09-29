# Terraform / OpenTofu Provider

The **Cosmian KMS Terraform provider** allows DevOps and platform engineering teams to manage
cryptographic keys, certificates, and access rights in Eviden KMS as infrastructure-as-code,
with full GitOps support.

| Attribute | Value |
|---|---|
| **Provider source** | `Cosmian/kms` |
| **Terraform Registry** | [registry.terraform.io/providers/Cosmian/kms](https://registry.terraform.io/providers/Cosmian/kms) |
| **GitHub repository** | [github.com/Cosmian/terraform-provider-kms](https://github.com/Cosmian/terraform-provider-kms) |
| **Current version** | v0.1.1 |
| **License** | Mozilla Public License 2.0 |
| **KMS version** | Eviden KMS ≥ 5.0 |

## Requirements

- [Terraform](https://developer.hashicorp.com/terraform/downloads) ≥ 1.0 or
  [OpenTofu](https://opentofu.org/) ≥ 1.6
- A running Eviden KMS instance (see [installation guide](../installation/installation_getting_started.md))

## Installation

Declare the provider in your Terraform configuration:

```hcl
terraform {
  required_providers {
    kms = {
      source  = "Cosmian/kms"
      version = "~> 0.1"
    }
  }
}
```

Then run:

```bash
terraform init
```

## Provider Configuration

### API key authentication (recommended)

```hcl
provider "kms" {
  server_url = "https://kms.example.com:9998"
  api_key    = var.kms_api_key   # or set COSMIAN_KMS_API_KEY env var
}
```

### mTLS client certificate authentication

```hcl
provider "kms" {
  server_url    = "https://kms.example.com:9998"
  tls_cert_file = "/etc/kms/client.crt"
  tls_key_file  = "/etc/kms/client.key"
  ca_cert_file  = "/etc/kms/ca.pem"   # optional — verify KMS server certificate
}
```

### Environment variables

All provider arguments can be supplied via environment variables, which is the recommended
approach for CI/CD pipelines:

| Argument | Environment variable |
|---|---|
| `server_url` | `COSMIAN_KMS_SERVER_URL` |
| `api_key` | `COSMIAN_KMS_API_KEY` |

```bash
export COSMIAN_KMS_SERVER_URL="https://kms.example.com:9998"
export COSMIAN_KMS_API_KEY="my-secret-api-key"
terraform apply
```

## Resources

### `kms_symmetric_key`

Creates an AES symmetric key via KMIP `Create`.

```hcl
resource "kms_symmetric_key" "data_key" {
  algorithm       = "AES"
  key_length_bits = 256
  name            = "database-encryption-key"
  tags            = ["env=prod", "team=data"]
}

output "data_key_uid" {
  value = kms_symmetric_key.data_key.id
}
```

#### Arguments

| Argument | Type | Required | Description |
|---|---|---|---|
| `algorithm` | string | yes | Cryptographic algorithm. `AES` (default) |
| `key_length_bits` | number | yes | Key size in bits: `128`, `192`, or `256` |
| `name` | string | no | Human-readable name stored as a KMIP `Name` attribute |
| `tags` | list(string) | no | List of `key=value` tags attached to the object |

#### Attributes

| Attribute | Description |
|---|---|
| `id` | KMS UID of the created key (UUID) |

---

### `kms_key_pair`

Creates an asymmetric key pair via KMIP `CreateKeyPair`.

```hcl
resource "kms_key_pair" "signing_pair" {
  algorithm       = "RSA"
  key_length_bits = 4096
  name            = "code-signing"
}

output "private_key_uid" {
  value = kms_key_pair.signing_pair.private_key_uid
}

output "public_key_uid" {
  value = kms_key_pair.signing_pair.public_key_uid
}
```

#### Arguments

| Argument | Type | Required | Description |
|---|---|---|---|
| `algorithm` | string | yes | `RSA`, `EC` |
| `key_length_bits` | number | yes | RSA: `2048`, `3072`, `4096`. EC: curve size (`256`, `384`, `521`) |
| `name` | string | no | Human-readable key pair name |
| `tags` | list(string) | no | Tags for both keys |

#### Attributes

| Attribute | Description |
|---|---|
| `private_key_uid` | KMS UID of the private key |
| `public_key_uid` | KMS UID of the public key |

---

### `kms_certificate`

Creates or imports an X.509 certificate via KMIP `Certify`.

```hcl
resource "kms_key_pair" "ca_pair" {
  algorithm       = "RSA"
  key_length_bits = 4096
  name            = "internal-ca"
}

resource "kms_certificate" "internal_ca" {
  subject_name  = "CN=Internal CA,O=Example,C=FR"
  key_pair_uid  = kms_key_pair.ca_pair.private_key_uid
  is_ca         = true
  validity_days = 3650
}
```

#### Arguments

| Argument | Type | Required | Description |
|---|---|---|---|
| `subject_name` | string | yes | Distinguished Name (DN) of the certificate subject |
| `key_pair_uid` | string | yes | UID of the KMS private key to sign with |
| `is_ca` | bool | no | Whether to add the CA basic constraint. Default: `false` |
| `validity_days` | number | no | Certificate validity period in days. Default: `365` |
| `tags` | list(string) | no | Tags attached to the certificate object |

#### Attributes

| Attribute | Description |
|---|---|
| `id` | KMS UID of the certificate |

---

### `kms_access_right`

Grants a user access rights to a KMS object via the KMS grant endpoint.

```hcl
resource "kms_access_right" "alice_can_decrypt" {
  object_uid = kms_symmetric_key.data_key.id
  user_id    = "alice@example.com"
  operations = ["Get", "Decrypt"]
}
```

#### Arguments

| Argument | Type | Required | Description |
|---|---|---|---|
| `object_uid` | string | yes | UID of the KMS object to grant access to |
| `user_id` | string | yes | Identity of the user (email, sub claim, or DN) |
| `operations` | list(string) | yes | KMIP operation names to grant: `Get`, `Decrypt`, `Encrypt`, `Sign`, `Verify`, `Export`, `Destroy`, … |

## Data Sources

### `data.kms_symmetric_key`

Reads an existing symmetric key by UID.

```hcl
data "kms_symmetric_key" "existing_key" {
  unique_identifier = "550e8400-e29b-41d4-a716-446655440000"
}
```

### `data.kms_key_pair`

Reads an existing key pair.

```hcl
data "kms_key_pair" "existing_pair" {
  private_key_uid = "uuid-of-private-key"
}
```

### `data.kms_access_list`

Lists all access rights on a KMS object.

```hcl
data "kms_access_list" "key_grants" {
  object_uid = kms_symmetric_key.data_key.id
}

output "granted_users" {
  value = data.kms_access_list.key_grants.users
}
```

## Import

All resources support `terraform import` to bring existing KMS objects under Terraform management.

```bash
# Symmetric key
terraform import kms_symmetric_key.data_key 550e8400-e29b-41d4-a716-446655440000

# Key pair — format: private_uid:public_uid
terraform import kms_key_pair.signing_pair \
  aaaa0000-0000-0000-0000-000000000001:bbbb0000-0000-0000-0000-000000000002

# Certificate
terraform import kms_certificate.internal_ca cccc0000-0000-0000-0000-000000000003
```

## Complete example

The following configuration creates a 256-bit AES key and a 4096-bit RSA signing pair, then
grants `alice@example.com` decrypt rights on the AES key:

```hcl
terraform {
  required_providers {
    kms = {
      source  = "Cosmian/kms"
      version = "~> 0.1"
    }
  }
}

provider "kms" {
  # server_url and api_key read from COSMIAN_KMS_SERVER_URL / COSMIAN_KMS_API_KEY
}

resource "kms_symmetric_key" "app_dek" {
  algorithm       = "AES"
  key_length_bits = 256
  name            = "app-data-encryption-key"
  tags            = ["app=myapp", "env=prod"]
}

resource "kms_key_pair" "app_signing" {
  algorithm       = "RSA"
  key_length_bits = 4096
  name            = "app-signing-key"
  tags            = ["app=myapp", "env=prod"]
}

resource "kms_access_right" "alice_decrypt" {
  object_uid = kms_symmetric_key.app_dek.id
  user_id    = "alice@example.com"
  operations = ["Get", "Decrypt"]
}

output "dek_uid"         { value = kms_symmetric_key.app_dek.id }
output "private_key_uid" { value = kms_key_pair.app_signing.private_key_uid }
output "public_key_uid"  { value = kms_key_pair.app_signing.public_key_uid }
```

Apply it against a local KMS instance:

```bash
docker run -d -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest

export COSMIAN_KMS_SERVER_URL=http://localhost:9998
terraform init
terraform apply
```

## Local development and testing

Clone the provider repository and build the binary:

```bash
git clone https://github.com/Cosmian/terraform-provider-kms
cd terraform-provider-kms
make build     # produces ./terraform-provider-kms
```

Configure Terraform to use the local binary instead of the registry version by creating or
editing `~/.terraformrc`:

```hcl
provider_installation {
  dev_overrides {
    "Cosmian/kms" = "/absolute/path/to/terraform-provider-kms"
  }
  direct {}
}
```

Run the acceptance tests against a local KMS server:

```bash
docker run -d -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest

export TF_ACC=1
export COSMIAN_KMS_SERVER_URL=http://localhost:9998
make testacc
```

## Related

- [Terraform Registry — Cosmian/kms](https://registry.terraform.io/providers/Cosmian/kms)
- [Provider GitHub repository](https://github.com/Cosmian/terraform-provider-kms)
- [OpenAPI / REST API](./openapi.md)
- [Kubernetes integrations](./kubernetes/index.md)
- [Helm chart deployment](./kubernetes/helm.md)
