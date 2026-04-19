# Cosmian KMS

[![CI](https://img.shields.io/github/actions/workflow/status/Cosmian/kms/main.yml?branch=develop&label=CI&logo=github)](https://github.com/Cosmian/kms/actions/workflows/main.yml) [![Tests](https://img.shields.io/github/actions/workflow/status/Cosmian/kms/pr.yml?branch=develop&label=Packaging&logo=github)](https://github.com/Cosmian/kms/actions/workflows/pr.yml) [![Release](https://img.shields.io/github/v/release/Cosmian/kms)](https://github.com/Cosmian/kms/releases) [![Docs](https://img.shields.io/badge/Docs-cosmian.com-0A84FF?logo=readthedocs&logoColor=white)](https://docs.cosmian.com/key_management_system/) [![Container](https://img.shields.io/badge/ghcr.io%2Fcosmian%2Fkms-Image-2496ED?logo=docker&logoColor=white)](https://github.com/Cosmian/kms/pkgs/container/kms) [![Security](https://img.shields.io/badge/Security-Policy-0A84FF?logo=github&logoColor=white)](SECURITY.md) [![License](https://img.shields.io/badge/License-BSL%201.1-blue)](LICENSE) [![FIPS](https://img.shields.io/badge/FIPS%20140--3-Mode-blue)](./documentation/docs/fips.md)

The **Cosmian KMS** is a high-performance, source-available [FIPS 140-3 compliant](./documentation/docs/fips.md) server application written in [Rust](https://www.rust-lang.org/).

Online [documentation](https://docs.cosmian.com/key_management_system/).

![KMS WebUI](./documentation/docs/images/kms-ui.png)
<p align="center"><em>Built-in Web UI for administration and operations.</em></p>

The **Cosmian KMS** presents some unique features, such as:

- **Use cases**: [large-scale encryption/decryption](./documentation/docs/use_cases/encrypting_and_decrypting_at_scale.md) and [client-side/application-level encryption](./documentation/docs/use_cases/client_side_and_application_level_encryption.md), with support for signature at scale (including secp256k1 in non-FIPS mode).
- **Cloud and enterprise integrations**: [AWS XKS v2](./documentation/docs/integrations/cloud_providers/aws/xks.md), [Azure EKM](./documentation/docs/integrations/cloud_providers/azure/ekm.md), [Google Workspace CSE](./documentation/docs/integrations/cloud_providers/google_workspace_client_side_encryption_cse/getting_started/index.md), and [Microsoft 365 DKE](./documentation/docs/integrations/cloud_providers/microsoft_365_double_key_encryption_dke/index.md).
- **Databases**: [Oracle Database TDE](./documentation/docs/integrations/databases/oracle_tde.md), [Microsoft SQL Server External (EKM)](./documentation/docs/integrations/databases/ms_sql_server.md), [MongoDB](./documentation/docs/integrations/databases/mongodb.md), [MySQL Enterprise](./documentation/docs/integrations/databases/mysql.md), [PostgreSQL Percona](./documentation/docs/integrations/databases/percona.md), and [Snowflake Native App](./documentation/docs/integrations/databases/snowflake_native_app/index.md).
- **Disk encryption**: [Veracrypt](./documentation/docs/integrations/disk_encryption/veracrypt.md), [LUKS](./documentation/docs/integrations/disk_encryption/luks.md), and [Cryhod](./documentation/docs/integrations/disk_encryption/cryhod.md).
- **Other integrations**: [OpenSSH](./documentation/docs/integrations/openssh.md), [Synology DSM](./documentation/docs/integrations/storage/synology_dsm.md), [Veeam Backup & Replication](./documentation/docs/integrations/storage/veeam.md), [VMware vCenter Trust Key Provider](./documentation/docs/integrations/storage/vcenter.md), and [PySpark/Databricks Python UDF](./documentation/docs/integrations/storage/user_defined_function_for_pyspark_databricks_in_python/index.md).
- **Security and standards**: [FIPS 140-3](./documentation/docs/certifications_and_compliance/fips.md), [KMIP 1.0-2.1 binary and JSON TTLV support](./documentation/docs/kmip_support/introduction/index.md), and [state-of-the-art authentication mechanisms](./documentation/docs/configuration/authentication.md).
- **HSM support**: [Utimaco, SmartCard-HSM/Nitrokey HSM 2, Proteccio, Crypt2pay, and others](./documentation/docs/hsm_support/introduction/index.md), with KMS keys wrapped by HSMs.
- **Operations**: full-featured [CLI and graphical clients](https://docs.cosmian.com/kms_clients/), [high-availability mode](./documentation/docs/installation/high_availability_mode.md), [confidential cloud deployment](./documentation/docs/installation/marketplace_guide.md), and [OpenTelemetry integration](./documentation/docs/configuration/logging.md).

The **Cosmian KMS** is both a Key Management System and a Public Key Infrastructure. As a KMS, it is designed to manage the lifecycle of keys and provide scalable cryptographic services such as on-the-fly key generation, encryption, and decryption operations.

The **Cosmian KMS** supports all the standard NIST cryptographic algorithms as well as advanced post-quantum cryptography algorithms such as [Covercrypt](https://github.com/Cosmian/cover_crypt). Please refer to the list of [supported algorithms](./documentation/docs/algorithms.md).

As a **PKI** it can manage root and intermediate certificates, sign and verify certificates, use their public keys to encrypt and decrypt data. Certificates can be exported under various formats, including _PKCS#12_ modern and legacy flavor, to be used in various applications, such as in _S/MIME_ encrypted emails.

The **Cosmian KMS** has extensive online [documentation](https://docs.cosmian.com/key_management_system/).

## 🚀 Quick start

Pre-built binaries [are available](https://package.cosmian.com/kms/5.20.1/) for Linux, MacOS, and Windows, as well as Docker images. To run the server binary, OpenSSL must be available in your path (see "building the KMS" below for details); other binaries do not have this requirement.

Using Docker to quick-start a Cosmian KMS server on `http://localhost:9998` that stores its data inside the container, run the following command:

```sh
docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest
```

Then, use the CLI to issue commands to the KMS. The CLI, called `cosmian`, can be either:

- installed with `cargo install ckms`
- downloaded from [Cosmian packages](https://package.cosmian.com/kms/)
- built and launched from the [GitHub project](https://github.com/Cosmian/cli) by running

    ```sh
    cargo build --bin ckms
    ```

### ▶️ Example

1. Create a 256-bit symmetric key

    ```sh
    ➜ ckms sym keys create --number-of-bits 256 --algorithm aes --tag my-key-file
    ...
    The symmetric key was successfully generated.
      Unique identifier: 87e9e2a8-4538-4701-aa8c-e3af94e44a9e

      Tags:
        - my-key-file
    ```

2. Encrypt the `image.png` file with AES GCM using the key

    ```sh
    ➜ ckms sym encrypt --tag my-key-file --output-file image.enc image.png
    ...
    The encrypted file is available at "image.enc"
    ```

3. Decrypt the `image.enc` file using the key

    ```sh
    ➜ ckms sym decrypt --tag my-key-file --output-file image2.png image.enc
    ...
    The decrypted file is available at "image2.png"
    ```

See the [documentation](https://docs.cosmian.com/key_management_system/) for more.

## ⭐ Why Cosmian KMS

- Performance: built in Rust for low-latency crypto and high throughput.
- Trust by design: FIPS 140-3 mode by default; non-FIPS for broader algorithm access when needed.
- Interoperable: full KMIP 1.0–2.1 support, PKCS#11 integrations, and rich client tooling.
- HSM-first: optional HSM key-wrapping and vendor modules (Utimaco, SmartCard-HSM, Proteccio, Crypt2pay…).
- Cloud-native: official Docker image, simple horizontal scaling, and OpenTelemetry observability.
- End-to-end: server, CLI, and web UI for a complete developer and operator experience.
- **Key auto-rotation**: policy-driven background rotation for plain, wrapped, and wrapping keys — see [Key Auto-Rotation Policy](./documentation/docs/kmip_support/key_auto_rotation.md).

## 🎯 Top Use Cases

- Application‑level encryption at scale (files, objects, datasets) with centralized key lifecycle.
- Database TDE and integration (Oracle TDE, Percona PostgreSQL, MongoDB, MySQL) via KMIP/PKCS#11.
- Enterprise integrations: Google Workspace CSE, Microsoft DKE, Microsoft SQL Server External (EKM), AWS XKS v2, and Azure EKM.
- HSM-backed key protection and policy‑driven access controls.
- PKI operations: issue, sign, validate, and automate certificate lifecycles.

## 🔒 Security & Compliance

- FIPS 140-3 mode on by default; switch to `--features non-fips` for extended algorithms.
- Reproducible builds via Nix; release artifacts ship with SHA-256 checksums.
- Software Bill of Materials (SBOM) and vulnerability reports for server and CLI (`ckms`):
      - CycloneDX (server): [`sbom/server/fips/static/bom.cdx.json`](sbom/server/fips/static/bom.cdx.json)
      - SPDX (server): [`sbom/server/fips/static/bom.spdx.json`](sbom/server/fips/static/bom.spdx.json)
      - Vulnerabilities (server): [`sbom/server/fips/static/vulns.csv`](sbom/server/fips/static/vulns.csv)
      - CycloneDX (ckms CLI): [`sbom/ckms/fips/static/bom.cdx.json`](sbom/ckms/fips/static/bom.cdx.json)
      - Overview: [`sbom/README.md`](sbom/README.md)
    - Cryptography Bill of Materials (CBOM): full inventory of cryptographic assets (algorithms, libraries, parameters) in CycloneDX 1.6 format.
        - [`cbom/cbom.cdx.json`](cbom/cbom.cdx.json) — generated by `.github/scripts/sbom/generate_cbom.py`
-
  Observability built-in with OpenTelemetry metrics/traces. See [`OTLP_METRICS.md`](monitoring/OTLP_METRICS.md).

[TOC]

## 🔐 HSM support

| HSM                                        | Status |
| ------------------------------------------ | ------ |
| Proteccio (Bull Atos)                      | ✅      |
| Crypt2pay                                  | ✅      |
| Utimaco SecurityServer                     | ✅      |
| CardContact SmartCard-HSM / Nitrokey HSM 2 | ✅      |
| SoftHSM2 (testing)                         | ✅      |
| AWS CloudHSM                               | 🚧      |
| Azure Dedicated HSM                        | 🚧      |
| GCP Cloud HSM                              | 🚧      |

## 🔗 Integrations

> Legend: ✅ implemented · 🚧 not yet implemented

### ☁️ Cloud Provider — External Key Management

Cloud providers offer mechanisms that let you hold cryptographic keys outside their infrastructure.
There are three distinct delegation models:

| Term     | Meaning                                                                                                                                    |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| **XKS**  | AWS External Key Store — every encrypt/decrypt is proxied live to your KMS; the key material never enters AWS.                             |
| **EKM**  | GCP External Key Manager — same live-proxy model; Google never holds the key material.                                                     |
| **DKE**  | Microsoft Double Key Encryption — one key lives in Azure/M365, the second key lives exclusively in your KMS; both are required to decrypt. |
| **HYOK** | Hold Your Own Key (Oracle) — OCI Vault External KMS; every encrypt/decrypt is proxied live to your KMS; the key material never enters OCI. |
| **BYOK** | Bring Your Own Key — you generate key material and import it into the provider's KMS; the provider then holds a copy.                      |
| **CMK**  | Customer-Managed Key — the provider generates and stores the key in their KMS, but you control lifecycle (rotate, disable, delete).        |

#### Amazon Web Services (AWS)

AWS XKS is a **single proxy API** that AWS KMS calls on behalf of every service — S3, EBS, RDS, DynamoDB, Secrets Manager, etc. all route through the same endpoint. Implementing the [XKS Proxy API](https://github.com/aws/aws-kms-xks-proxy) once gives Cosmian KMS live-proxy coverage for all XKS-capable AWS services with no per-service work.

| Delegation model     | Description                                                                                                                                                                                                                                                                  | Status |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| **XKS** (live proxy) | Key material never enters AWS; every encrypt/decrypt is proxied to Cosmian KMS — covers all AWS services that support KMS encryption (S3, EBS, RDS, DynamoDB, Secrets Manager, SQS, SNS, Redshift, OpenSearch, EMR, Glue, Lambda…) — [docs](./documentation/docs/integrations/cloud_providers/aws/xks.md) | ✅      |
| **BYOK**             | Key material generated by you and imported once into AWS KMS; AWS holds a copy                                                                                                                                                                                               | ✅      |
| **CMK**              | Key generated and stored inside AWS KMS; you control lifecycle only                                                                                                                                                                                                          | 🚧      |

#### Microsoft Azure

Unlike AWS XKS or GCP EKM, Azure has no single proxy gateway — each service integrates with Azure Key Vault independently. Both EKM and DKE are live-proxy models where key material never leaves Cosmian KMS; DKE is unique in requiring both your key and Microsoft's key to decrypt.

| Delegation model     | Description                                                                                                                                                                                                                                      | Status |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------ |
| **EKM** (live proxy) | Key material never leaves Cosmian KMS; Azure services proxy encrypt/decrypt operations to Cosmian KMS via mTLS — [docs](./documentation/docs/integrations/cloud_providers/azure/ekm.md)                                                                                   | ✅      |
| **DKE** (live proxy) | Key material never leaves Cosmian KMS; M365 / Purview requires both your key and Microsoft's key to decrypt                                                                                                                                      | ✅      |
| **BYOK**             | Key material generated by you, imported once into Azure Key Vault; Azure holds a copy — applies to Azure Information Protection (AIP)                                                                                                            | ✅      |
| **BYOK / CMK**       | Key imported or generated inside Azure Key Vault; applies to all remaining Azure data services (Storage, Disk Encryption, SQL/Managed Instance TDE, Cosmos DB, Synapse, Databricks, Container Registry, Monitor, Service Bus, ASK etcd, Backup…) | ✅      |

#### Google Cloud Platform (GCP)

GCP EKM is a **single proxy gateway** — like AWS XKS, implementing EKM once covers all CMEK-capable GCP services automatically (Cloud Storage, BigQuery, Cloud SQL, GKE, Pub/Sub, Spanner, Vertex AI, Cloud Functions, Artifact Registry, Secret Manager, Cloud Logging…). Workspace CSE uses the same live-proxy model.

| Delegation model               | Description                                                                                                                                             | Status |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| **EKM** (live proxy)           | Key material never enters GCP; every encrypt/decrypt is proxied to Cosmian KMS — covers all CMEK-capable GCP services                                   | ✅      |
| **Workspace CSE** (live proxy) | Google Workspace Client-Side Encryption; keys held exclusively in Cosmian KMS                                                                           | ✅      |
| **CSEK**                       | Customer-Supplied Encryption Key: symmetric key generated in Cosmian KMS, wrapped with Google's CSEK certificate and supplied per-request — [docs](./documentation/docs/integrations/cloud_providers/google_gcp/csek.md) | ✅      |
| **BYOK / CMEK**                | Key material generated in Cosmian KMS, wrapped with Google's import wrapping key, and imported into Cloud KMS — [docs](./documentation/docs/integrations/cloud_providers/google_gcp/cmek.md)                           | ✅      |
| **CMK**                        | Key generated and stored in Cloud KMS; you control lifecycle only                                                                                       | 🚧      |

#### Oracle Cloud Infrastructure (OCI)

OCI Vault **External KMS** (HYOK) is a **single proxy gateway** — implementing it once covers all OCI services that support customer-managed keys (Block Volumes, Object Storage, File Storage, Autonomous Database, Oracle Database Service, Kubernetes Secrets in OKE, Streaming, Functions…).

| Delegation model                     | Description                                                                                                                                                                                                         | Status |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| **HYOK / External KMS** (live proxy) | Key material never enters OCI; every encrypt/decrypt is proxied to Cosmian KMS — covers all OCI services that support Vault External KMS (Block Volumes, Object Storage, File Storage, Autonomous DB, OKE secrets…) | 🚧      |
| **BYOK**                             | Key material generated by you and imported once into OCI Vault; Oracle holds a copy                                                                                                                                 | 🚧      |
| **CMK**                              | Key generated and stored in OCI Vault; you control lifecycle only                                                                                                                                                   | 🚧      |

---

### 🗄️ Database Integrations

| Product             | Integration                                                                                                                                                                           | Status |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| Oracle Database     | TDE via PKCS#11 ([docs](./documentation/docs/integrations/databases/oracle_tde.md))                                                                                                  | ✅      |
| MongoDB             | CSFLE / Queryable Encryption via KMIP ([docs](./documentation/docs/integrations/databases/mongodb.md))                                                                                | ✅      |
| MySQL Enterprise    | TDE via KMIP ([docs](./documentation/docs/integrations/databases/mysql.md))                                                                                                          | ✅      |
| Percona PostgreSQL  | TDE via KMIP ([docs](./documentation/docs/integrations/databases/percona.md))                                                                                                        | ✅      |
| Microsoft SQL Server | External Key Management (EKM) via PKCS#11 ([docs](./documentation/docs/integrations/databases/ms_sql_server.md))                                                                    | ✅      |
| Snowflake           | Native App — column-level encryption via KMIP ([docs](./documentation/docs/integrations/databases/snowflake_native_app/index.md))                                                    | ✅      |

### 💿 Disk Encryption

| Product   | Integration                                                                                                               | Status |
| --------- | ------------------------------------------------------------------------------------------------------------------------- | ------ |
| VeraCrypt | Virtual disk encryption via PKCS#11 ([docs](./documentation/docs/integrations/disk_encryption/veracrypt.md))             | ✅      |
| LUKS      | Linux disk encryption via PKCS#11 ([docs](./documentation/docs/integrations/disk_encryption/luks.md))                   | ✅      |
| Cryhod    | Disk encryption ([docs](./documentation/docs/integrations/disk_encryption/cryhod.md))                                    | ✅      |

### 💾 Storage Integrations

| Product                | Integration                                                                                                                                                          | Status |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| VMware vCenter         | Trust Key Provider ([docs](./documentation/docs/integrations/storage/vcenter.md))                                                                                            | ✅      |
| Synology DSM           | NAS volume encryption via KMIP ([docs](./documentation/docs/integrations/storage/synology_dsm.md))                                                                           | ✅      |
| Veeam Backup           | Backup encryption key management via KMIP ([docs](./documentation/docs/integrations/storage/veeam.md))                                                                        | ✅      |
| Big Data / Python UDFs | Bulk encrypt/decrypt for PySpark / Databricks ([docs](./documentation/docs/integrations/storage/user_defined_function_for_pyspark_databricks_in_python/index.md))             | ✅      |

### 🔗 Other Integrations

| Product  | Integration                                                                                                                  | Status |
| -------- | ---------------------------------------------------------------------------------------------------------------------------- | ------ |
| OpenSSH  | Certificate-based authentication ([docs](./documentation/docs/integrations/openssh.md))                                     | ✅      |
| S/MIME   | Email encryption ([docs](./documentation/docs/integrations/smime.md))                                                        | ✅      |
| PyKMIP   | PyKMIP-compatible interface for testing and Synology DSM ([docs](./documentation/docs/integrations/pykmip.md))               | ✅      |

---

---

<!-- KMIP_SUPPORT_START -->
<!-- This section is auto-generated from documentation/docs/kmip/support.md by scripts/update_readme_kmip.py. Do not edit manually. -->
## KMIP support by Cosmian KMS

This page summarizes the KMIP coverage in Cosmian KMS. The support status is
derived from the actual implementation in `crate/server/src/core/operations`.

**Cosmian KMS Server supports KMIP versions:** 2.1, 2.0, 1.4, 1.3, 1.2, 1.1, 1.0

Legend:

- ✅ Fully supported
- ❌ Not implemented
- 🚫 Deprecated
- N/A Not applicable (operation/attribute not defined in that KMIP version)

### KMIP Baseline Profile Compliance

**Baseline Server:** ✅ Compliant (all 9 required + 18/18 optional)

The Baseline Server profile (defined in KMIP Profiles v2.1 Section 4.1) requires:

- **Required operations:** Discover Versions, Query, Create, Register, Get, Destroy, Locate, Activate, Revoke
- **Optional operations:** Many additional operations for extended functionality

### KMIP Coverage

#### Messages

| Message          | Support |
| ---------------- | ------: |
| Request Message  |      ✅ |
| Response Message |      ✅ |

#### Operations by KMIP Version

The following table shows operation support across all KMIP versions.

| Operation | 1.0 | 1.1 | 1.2 | 1.3 | 1.4 | 2.0 | 2.1 |
| --------- | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: |
| Activate               |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Add Attribute          |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Archive                |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Cancel                 |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Certify                |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Check                  |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Create                 |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Create Key Pair        |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Create Split Key       |   N/A   |   N/A   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Decrypt                |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Delete Attribute       |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| DeriveKey              |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Destroy                |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Discover Versions      |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Encrypt                |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Export                 |   N/A   |   N/A   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |
| Get                    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Get Attribute List     |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Get Attributes         |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Get Usage Allocation   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Hash                   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Import                 |   N/A   |   N/A   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |
| Join Split Key         |   N/A   |   N/A   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Locate                 |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| MAC                    |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| MAC Verify             |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Notify                 |   N/A   |   N/A   |   N/A   |   N/A   |   N/A   |    ❌    |    ❌    |
| Obtain Lease           |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Poll                   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Put                    |   N/A   |   N/A   |   N/A   |   N/A   |   N/A   |    ❌    |    ❌    |
| Query                  |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| RNG Retrieve           |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| RNG Seed               |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Re-certify             |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Re-key                 |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Re-key Key Pair        |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Recover                |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Register               |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Revoke                 |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Set Attribute (Modify) |   N/A   |   N/A   |   N/A   |   N/A   |   N/A   |    ✅    |    ✅    |
| Sign                   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Signature Verify       |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Validate               |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |

#### Methodology

- Operations marked ✅ are backed by a Rust implementation file under `crate/server/src/core/operations`.
- Operations marked ❌ are defined in the KMIP specification but not implemented in Cosmian KMS.
- Operations marked N/A do not exist in that particular KMIP version.
- This documentation is auto-generated by analyzing source code and KMIP specifications.

If you spot a mismatch or want to extend coverage, please open an issue or PR.

#### Managed Objects

The following table shows managed object support across all KMIP versions.

| Managed Object | 1.0 | 1.1 | 1.2 | 1.3 | 1.4 | 2.0 | 2.1 |
| -------------- | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: |
| Certificate    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Symmetric Key  |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Public Key     |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Private Key    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Split Key      |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Template       |    🚫    |    🚫    |    🚫    |    🚫    |    🚫    |   N/A   |   N/A   |
| Secret Data    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Opaque Data    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| PGP Key        |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |

Notes:

- Opaque Object import support is present (see `import.rs`).
- PGP Key types appear in digest and attribute handling but full object import/register is not implemented, hence ❌.
- Template objects are deprecated in newer KMIP versions.

#### Base Objects

The following table shows base object support across all KMIP versions.

| Base Object | 1.0 | 1.1 | 1.2 | 1.3 | 1.4 | 2.0 | 2.1 |
| ----------- | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: |
| Attribute                                |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Credential                               |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Key Block                                |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Key Value                                |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Key Wrapping Data                        |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Key Wrapping Specification               |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Transparent Key Structures               |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |   N/A   |   N/A   |
| Template-Attribute Structures            |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |   N/A   |   N/A   |
| Server Information                       |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Extension Information                    |   N/A   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Data                                     |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Data Length                              |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Signature Data                           |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| MAC Data                                 |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Nonce                                    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Correlation Value                        |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Init Indicator                           |   N/A   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |
| Final Indicator                          |   N/A   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |
| RNG Parameters                           |   N/A   |   N/A   |   N/A   |    ❌    |    ❌    |    ❌    |    ❌    |
| Profile Information                      |   N/A   |   N/A   |   N/A   |    ❌    |    ❌    |    ❌    |    ❌    |
| Validation Information                   |   N/A   |   N/A   |   N/A   |    ❌    |    ❌    |    ❌    |    ❌    |
| Capability Information                   |   N/A   |   N/A   |   N/A   |    ❌    |    ❌    |    ❌    |    ❌    |
| Authenticated Encryption Additional Data |   N/A   |   N/A   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |
| Authenticated Encryption Tag             |   N/A   |   N/A   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |

Notes:

- AEAD Additional Data and Tag are supported in encrypt/decrypt APIs.
- Nonce and RNG Parameter are used by symmetric encryption paths.
- Base objects are fundamental structures present across all KMIP versions.

#### Transparent Key Structures

The following table shows transparent key structure support across all KMIP versions.

| Structure | 1.0 | 1.1 | 1.2 | 1.3 | 1.4 | 2.0 | 2.1 |
| --------- | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: |
| Symmetric Key            |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| DSA Private Key          |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| DSA Public Key           |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| RSA Private Key          |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| RSA Public Key           |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| DH Private Key           |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| DH Public Key            |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| EC Private Key           |   N/A   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |
| EC Public Key            |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| ECDSA Private Key        |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |   N/A   |   N/A   |
| ECDSA Public Key         |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |   N/A   |   N/A   |
| ECDH Private Key         |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |   N/A   |   N/A   |
| ECDH Public Key          |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |   N/A   |   N/A   |
| ECMQV Private Key        |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |   N/A   |   N/A   |
| ECMQV Public Key         |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |   N/A   |   N/A   |

Note: EC/ECDSA support is present; DH/DSA/ECMQV are not implemented.

#### Attributes

| Attribute | Current |
| --------- | ------: |
| Activation Date                     |       ✅ |
| Alternative Name                    |       ✅ |
| Always Sensitive                    |       ✅ |
| Application Specific Information    |       ✅ |
| Archive Date                        |       ✅ |
| Attribute Index                     |       ✅ |
| Certificate Attributes              |       ✅ |
| Certificate Length                  |       ✅ |
| Certificate Type                    |       ✅ |
| Comment                             |       ✅ |
| Compromise Date                     |       ✅ |
| Compromise Occurrence Date          |       ✅ |
| Contact Information                 |       ✅ |
| Critical                            |       ✅ |
| Cryptographic Algorithm             |       ✅ |
| Cryptographic Domain Parameters     |       ✅ |
| Cryptographic Length                |       ✅ |
| Cryptographic Parameters            |       ✅ |
| Cryptographic Usage Mask            |       ✅ |
| Deactivation Date                   |       ✅ |
| Description                         |       ✅ |
| Destroy Date                        |       ✅ |
| Digest                              |       ✅ |
| Digital Signature Algorithm         |       ✅ |
| Extractable                         |       ✅ |
| Fresh                               |       ✅ |
| Initial Date                        |       ✅ |
| Key Format Type                     |       ✅ |
| Key Value Location                  |       ✅ |
| Key Value Present                   |       ✅ |
| Last Change Date                    |       ✅ |
| Lease Time                          |       ✅ |
| Link                                |       ✅ |
| Name                                |       ✅ |
| Never Extractable                   |       ✅ |
| Nist Key Type                       |       ✅ |
| Object Group                        |       ✅ |
| Object Group Member                 |       ✅ |
| Object Type                         |       ✅ |
| Opaque Data Type                    |       ✅ |
| Original Creation Date              |       ✅ |
| PKCS#12 Friendly Name               |       ✅ |
| Process Start Date                  |       ✅ |
| Protect Stop Date                   |       ✅ |
| Protection Level                    |       ✅ |
| Protection Period                   |       ✅ |
| Protection Storage Masks            |       ✅ |
| Quantum Safe                        |       ✅ |
| Random Number Generator             |       ✅ |
| Revocation Reason                   |       ✅ |
| Rotate Date                         |       ✅ |
| Rotate Generation                   |       ✅ |
| Rotate Interval                     |       ✅ |
| Rotate Latest                       |       ✅ |
| Rotate Name                         |       ✅ |
| Rotate Offset                       |       ✅ |
| Sensitive                           |       ✅ |
| Short Unique Identifier             |       ✅ |
| State                               |       ✅ |
| Unique Identifier                   |       ✅ |
| Usage Limits                        |       ✅ |
| Vendor Attribute                    |       ✅ |
| X.509 Certificate Identifier        |       ✅ |
| X.509 Certificate Issuer            |       ✅ |
| X.509 Certificate Subject           |       ✅ |

Notes:

- GetAttributes returns a union of metadata attributes and those embedded in KeyBlock structures.
- "Vendor Attributes" are available via the Cosmian vendor namespace and are accessible via GetAttributes.
- A ✅ indicates the attribute is used or updated by at least one KMIP operation implementation in `crate/server/src/core/operations`, including attribute handlers (Add/Delete/Set/Get Attribute).
- Most attributes are present across all KMIP versions with some additions in newer versions.

<!-- KMIP_SUPPORT_END -->

## 🗄️ Repository content

The **Cosmian KMS** is written in [Rust](https://www.rust-lang.org/) and organized as a Cargo workspace with multiple crates. The repository contains the following main components:

### 🧰 Binaries

- **KMS Server** (`cosmian_kms`) - The main KMS server binary built from `crate/server`

### 🧱 Core Crates

#### 🖧 Server Infrastructure

- **`server`** - Main KMS server implementation with REST API, KMIP protocol support, and web UI
- **`server_database`** - Database abstraction layer supporting SQLite, PostgreSQL, MySQL, and Redis
- **`access`** - Permission and access control management system

Cosmian-only crate dependencies for the server crate (`crate/server`):

```mermaid
flowchart TD
    server[server]

    server --> access
    server --> base_hsm
    server --> server_database
    base_hsm --> hsm_loaders

    hsm_loaders --> smartcardhsm
    hsm_loaders --> crypt2pay
    hsm_loaders --> proteccio
    hsm_loaders --> softhsm2
    hsm_loaders --> utimaco
    hsm_loaders --> other

    server_database --> kmip
    server_database --> crypto
    server_database --> interfaces
```

#### 🧑‍💻 Client Libraries

- **`kms_client`** - High-level Rust client library for KMS server communication
- **`client_utils`** - Shared utilities for client implementations
- **`wasm`** - WebAssembly bindings for browser-based clients

#### 🔐 Cryptographic Components

- **`crypto`** - Core cryptographic operations and algorithm implementations
- **`kmip`** - Complete implementation of the KMIP (Key Management Interoperability Protocol) standard versions 1.0-2.1
- **`kmip-derive`** - Procedural macros for KMIP protocol serialization/deserialization

#### 🔐 Hardware Security Module (HSM) Support

- **`hsm/base_hsm`** - Base HSM abstraction layer
- **`hsm/smartcardhsm`** - Nitrokey HSM 2 resp. CardContact SmartCard-HSM
- **`hsm/crypt2pay`** - Crypt2pay HSM integration
- **`hsm/proteccio`** - Proteccio HSM integration
- **`hsm/softhsm2`** - SoftHSM2 integration for testing and development
- **`hsm/utimaco`** - Utimaco HSM integration
- **`hsm/other`** - Other HSMs support

#### 🗄️ Database Interfaces

- **`interfaces`** - Database and storage backend abstractions

#### 🧪 Development and Testing

- **`test_kms_server`** - Library for programmatic KMS server instantiation in tests
- **`cli`** - Legacy CLI crate (now primarily used for testing)

### 📁 Additional Directories

- **`documentation/`** - Comprehensive project documentation built with MkDocs
- **`examples/`** - Code examples and integration samples
- **`scripts/`** - Build and deployment scripts
- **`test_data/`** - Test fixtures and sample data
- **`ui/`** - Frontend web interface source code
- **`pkg/`** - Packaging configurations for Debian and RPM distributions

**Note:** Each crate contains its own README with detailed information. Please refer to these files for specific implementation details and usage instructions.

Find the [public documentation](https://docs.cosmian.com) of the KMS in the `documentation`
directory.

### 🏗️ Building and running the KMS

Two paths are supported:

- For production use, use Nix build: use the unified script `.github/scripts/nix.sh` for a pinned toolchain,
  reproducible FIPS builds (non-FIPS builds are tracked for consistency), and packaging.
- For development purpose, use traditional `cargo` command: `cargo build...`, `cargo test`

#### GLIBC Support

The following table shows the GLIBC versions and distribution support for **Cosmian KMS**:

| Distribution    | Version            | GLIBC | Support | End of Support |
| --------------- | ------------------ | ----- | ------- | -------------- |
| **Debian**      | 13 (Trixie)        | 2.40  | ✅       | TBD            |
| **Debian**      | 12 (Bookworm)      | 2.36  | ✅       | ~2028 (LTS)    |
| **Debian**      | 11 (Bullseye)      | 2.31  | ❌       | ~2026 (LTS)    |
| **Debian**      | 10 (Buster)        | 2.28  | ❌       | Jun 2024 (LTS) |
| **Debian**      | 9 (Stretch)        | 2.24  | ❌       | Jun 2022 (LTS) |
| **Rocky Linux** | 10                 | 2.40  | ✅       | TBD            |
| **Rocky Linux** | 9                  | 2.34  | ✅       | May 2032       |
| **Rocky Linux** | 8                  | 2.28  | ❌       | May 2029       |
| **Ubuntu**      | 25.04 (Plucky)     | 2.40  | ✅       | Jan 2026       |
| **Ubuntu**      | 24.04 LTS (Noble)  | 2.39  | ✅       | Apr 2029       |
| **Ubuntu**      | 22.04 LTS (Jammy)  | 2.35  | ✅       | Apr 2027       |
| **Ubuntu**      | 20.04 LTS (Focal)  | 2.31  | ❌       | Apr 2025       |
| **Ubuntu**      | 18.04 LTS (Bionic) | 2.27  | ❌       | Apr 2023       |

**Note:** Cosmian KMS requires **GLIBC 2.34** or higher (available in Debian 12+, Rocky Linux 9+, and Ubuntu 22.04+).

#### OpenSSL prerequisite

The following table shows the OpenSSL versions used by **Cosmian KMS** variants:

| OpenSSL Linkage | FIPS                                                                   | Non‑FIPS                                                         |
| --------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------- |
| Static          | Linkage: OpenSSL 3.6.0; runtime loads FIPS provider from OpenSSL 3.1.2 | Linkage: OpenSSL 3.6.0; runtime uses default/legacy providers    |
| Dynamic         | Linkage: OpenSSL 3.1.2; ships FIPS configs and provider OpenSSL 3.1.2  | Linkage: OpenSSL 3.6.0; ships `libssl`/`libcrypto` and providers |

Notes:

- FIPS builds include `fipsmodule.cnf` and the FIPS provider

#### ✨ Features

From version 5.4.0, the KMS runs in FIPS mode by default.
The non-FIPS mode can be enabled by passing the `--features non-fips` flag to `cargo build` or `cargo run`.

The `interop` feature enables KMIP interoperability test operations, which are disabled by default for security reasons.
These operations should only be enabled during testing: `cargo build --features interop` or `cargo test --features interop`.

All builds link against OpenSSL 3.6.0. FIPS variants ship the FIPS provider and `fipsmodule.cnf`; non‑FIPS variants use the default/legacy providers. For non‑Nix development, ensure OpenSSL 3.6.0+ is available.

#### 🖥️ Linux or macOS

Nix-based (reproducible FIPS builds):

```sh
# Run tests (defaults to 'all'; DB backends require services)
bash .github/scripts/nix.sh test

# Package artifacts (Linux → deb+rpm, macOS → dmg)
bash .github/scripts/nix.sh package
```

Simple (Cargo-only):

```sh
cargo build
cargo test --lib --workspace
cargo test --lib --workspace --features non-fips
```

#### 🪟 Windows

Follow the prerequisites below, or use the provided PowerShell helpers.

Prerequisites (manual):

1. Install Visual Studio (C++ workload + clang), Strawberry Perl, and `vcpkg`.
2. Install OpenSSL 3.6.0 with vcpkg:

In this project root directory, run:

```powershell
vcpkg install --triplet x64-windows-static  # arm64-windows-static for ARM64
$env:OPENSSL_DIR=(Get-Item .).FullName+"\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows-static"
```

For FIPS builds (to build fips.dll):

```powershell
Copy-Item -Path "vcpkg_fips.json" -Destination "vcpkg.json"
vcpkg install
vcpkg integrate install
```

PowerShell helpers (non-FIPS by default):

```powershell
. .github/scripts/cargo_build.ps1
BuildProject -BuildType release   # or debug

. .github/scripts/cargo_test.ps1
TestProject -BuildType release    # or debug
```

#### 📦 Packaging (DEB/RPM/DMG) and hashes

Use the Nix entrypoint to build packages:

```sh
# Linux
bash .github/scripts/nix.sh package           # builds deb + rpm
bash .github/scripts/nix.sh package deb       # build deb only
bash .github/scripts/nix.sh package rpm       # build rpm only

# macOS
bash .github/scripts/nix.sh package dmg
```

On success, a SHA-256 checksum file (.sha256) is written next to each generated package
(.deb/.rpm/.dmg) to ease verification and artifact distribution.

### 🧪 Running the unit and integration tests

Pull the test data using:

```sh
git submodule update --init --recursive
```

By default, tests are run using `cargo test` and an SQLCipher backend (called `sqlite`).
This can be influenced by setting the `KMS_TEST_DB` environment variable to

- `sqlite`, for plain SQLite
- `mysql` (requires a running MySQL or MariaDB server connected using a
  `"mysql://kms:kms@localhost:3306/kms"` URL)
- `postgresql` (requires a running PostgreSQL server connected using
  a `"postgresql://kms:kms@127.0.0.1:5432/kms"`URL)
- `redis-findex` (requires a running Redis server connected using a
  `"redis://localhost:6379"` URL)

Example: testing with a plain SQLite and some logging

```sh
RUST_LOG="error,cosmian_kms_server=info,cosmian_kms_cli=info" KMS_TEST_DB=sqlite cargo test
```

Alternatively, when writing a test or running a test from your IDE, the following can be inserted
at the top of the test:

```rust
unsafe {
set_var("RUST_LOG", "error,cosmian_kms_server=debug,cosmian_kms_cli=info");
set_var("RUST_BACKTRACE", "1");
set_var("KMS_TEST_DB", "redis-findex");
}
log_init(option_env!("RUST_LOG"));
```

### ⚙️ Development: running the server with cargo

To run the server with cargo, you need to set the `RUST_LOG` environment variable to the desired
log level and select the correct backend (which defaults to `sqlite`).

```sh
RUST_LOG="info,cosmian_kms_server=debug" \
cargo run --bin cosmian_kms --features non-fips -- \
--database-type redis-findex --database-url redis://localhost:6379 \
--redis-master-password secret --redis-findex-label label
```

### 🔧 Server parameters

If a configuration file is provided, parameters are set following this order:

- conf file (env variable `COSMIAN_KMS_CONF` set by default to `/etc/cosmian/kms.toml`)
- default (set on struct)

Otherwise, the parameters are set following this order:

- args in the command line
- env var
- default (set on struct)

## ☁️ Use the KMS inside a Cosmian VM on SEV/TDX

See the [Marketplace guide](documentation/docs/installation/marketplace_guide.md) for more details about Cosmian VM.

## 🏷️ Releases

All releases can be found in the public URL [package.cosmian.com](https://package.cosmian.com/kms/).

## 📈 Benchmarks

To run benchmarks, go to the `crate/test_kms_server` directory and run:

```sh
cargo bench
```

Typical values for single-threaded HTTP KMIP 2.1 requests
(zero network latency) are as follows

```text
- RSA PKCSv1.5:
    - encrypt
            - 2048 bits: 128 microseconds
            - 4096 bits: 175 microseconds
    - decrypt
            - 2048 bits: 830 microseconds
            - 4096 bits: 4120 microseconds
- RSA PKCS OAEP:
    - encrypt
            - 2048 bits: 134 microseconds
            - 4096 bits: 173 microseconds
    - decrypt
            - 2048 bits: 849 microseconds
            - 4096 bits: 3823 microseconds
- RSA PKCS KEY WRP (AES):
    - encrypt
            - 2048 bits: 142 microseconds
            - 4096 bits: 198 microseconds
    - decrypt
            - 2048 bits: 824 microseconds
            - 4096 bits: 3768 microseconds
- RSA Keypair creation (saved in KMS DB)
    -  2048 bits: 33 milliseconds
    -  4096 bits: 322 milliseconds
```

## 🤝 Community & Support

- Docs: `documentation/` and online docs at <https://docs.cosmian.com/key_management_system/>
- Issues: use GitHub Issues to report bugs and request features
- Contributing: see [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Security disclosures: see [`SECURITY.md`](SECURITY.md)
- License: see [`LICENSE`](LICENSE)
