# Azure Cloud HSM

Azure Cloud HSM is Microsoft's single-tenant, customer-managed HSM service. It ships its own PKCS#11 v2.40 library (`libazcloudhsm_pkcs11.so`), which is wired into the KMS's generic PKCS#11 implementation. The KMS passes the configured slot and password to that library; the network, partition, and client configuration remain in the Azure Cloud HSM client configuration.

The integration is supported on **Linux (x86_64)**.

> This is a different feature from [Azure EKM](../integrations/cloud_providers/azure/ekm.md): EKM is an Azure Managed HSM calling into Cosmian as an external key manager (reverse direction); this integration is Cosmian consuming Azure's own HSM hardware as one of its backend HSM vendors — the same direction as the AWS CloudHSM, GCP Cloud HSM, Utimaco, Proteccio, Crypt2Pay, and SmartCard HSM integrations.

## Azure Cloud HSM client setup

Install and configure the Azure Cloud HSM client on a Linux x86_64 host, following the [Azure Cloud HSM PKCS#11 Integration Guide](https://github.com/microsoft/MicrosoftAzureCloudHSM/blob/main/IntegrationGuides/Azure%20Cloud%20HSM%20PKCS11%20Integration%20Guide.pdf).

The KMS expects the PKCS#11 library at `/opt/azurecloudhsm/lib64/libazcloudhsm_pkcs11.so` (the default installation path). Override it with the `AZURE_CLOUD_HSM_PKCS11_LIB` environment variable if your installation differs:

```bash
export AZURE_CLOUD_HSM_PKCS11_LIB=/path/to/libazcloudhsm_pkcs11.so
```

The client configuration file, network addresses, partition, and credentials must be configured with the Azure Cloud HSM client tools before starting the KMS.

## Create a dedicated Crypto User

Do not reuse the Crypto Officer (CO) credentials in the KMS. Deploy and initialize an Azure Cloud HSM resource following the Integration Guide, then log in as the CO with `azcloudhsm_mgmt_util` and create a dedicated Crypto User (CU):

```bash
sudo ./azcloudhsm_mgmt_util ./azcloudhsm_resource.cfg
loginHSM CO <co_user> <co_password>
createUser CU <cu_user> <cu_password>
```

## Authentication

The PKCS#11 login PIN expected by Azure Cloud HSM for a Crypto User is the string `"<cu_user>:<cu_password>"`. Pass this combined string directly as the KMS `hsm_password` value; no other configuration is required.

## Find the slot id

`<slot_id>` is the PKCS#11 slot id of the partition, **not** the position of the slot in `C_GetSlotList`. Discover it with:

```bash
pkcs11-tool --module /opt/azurecloudhsm/lib64/libazcloudhsm_pkcs11.so --list-slots
```

`pkcs11-tool` prints each entry as `Slot <index> (0x<slot_id>)`; use the hexadecimal value in parentheses, written in decimal for `hsm_slot` (for example, `Slot 0 (0x1)` means `hsm_slot = [1]`). Passing the list index instead of the real slot id fails with `CKR_SLOT_ID_INVALID`.

## KMS configuration

At least one slot and its corresponding PIN must be configured.

### Configuration via config file

When using the [TOML configuration file](../configuration/server_configuration_file.md#toml-configuration-file), enable HSM support by setting these parameters:

```toml
hsm_model = "azure_cloud_hsm"
hsm_admin = "<HSM_ADMIN_USERNAME>" # defaults to "admin"
hsm_slot = [<slot_id>]
hsm_password = ["<cu_user>:<cu_password>"]
```

> **_NOTE:_**  `hsm_slot` and `hsm_password` must always be arrays, even if only one slot is used.
>
> The order of the passwords must match the order of the slots in the `hsm_slot` array.

### Configuration via command-line

HSM support can also be enabled with command-line arguments:

```shell
--hsm-model "azure_cloud_hsm" \
--hsm-admin "<HSM_ADMIN_USERNAME>" \
--hsm-slot <slot_id> --hsm-password "<cu_user>:<cu_password>"
```

The `hsm-model` parameter is the HSM model. Use `azure_cloud_hsm`.

The `hsm-admin` parameter is the username of the HSM administrator. The HSM administrator is the only user who can create objects on the HSM via the KMIP `Create` operation and delegate other operations to other users.

The `hsm-slot` and `hsm-password` parameters are the PKCS#11 slot id and CU login PIN of the HSM slots used by the KMS. These options can be repeated to configure multiple slots. Set `KMS_HSM_PASSWORD` to keep the password out of the `ps` output.

## Capabilities and limits

The vendor library is a PKCS#11 v2.40 library, so the KMS adapts as follows (see [Algorithm support by model](algorithm_support.md) for the full matrix):

- AES-GCM uses classic `C_EncryptInit` with an HSM-generated IV; caller-supplied IVs and the PKCS#11 v3.0 message-based functions are not available.
- The firmware does not store `CKA_START_DATE` / `CKA_END_DATE`, so [HSM key auto-rotation](../kmip_support/key_rotation/hsm.md) is unavailable: the `x-rotate-interval` attribute is rejected.
- `CKA_SENSITIVE` is not set explicitly when generating keys.
- Only the NIST P-256 and P-384 curves are supported for sign/verify, and there is no EdDSA signing. Sign Recover and Verify Recover are not supported.
- Objects are listed through `FindObjects` in pages of 64.

## Development and CI validation

There is no free/local Azure Cloud HSM simulator equivalent to SoftHSM2. CI connects to a persistent, pre-provisioned partition (the cluster is currently torn down, so the live job is disabled in `.github/workflows/test_all.yml`) and runs:

```bash
mise run test:hsm-azure-cloud-hsm --variant non-fips
```

This installs the Azure Cloud HSM Client SDK, starts the `azcloudhsm_client` daemon (through a VPN tunnel if the partition is not directly reachable), and runs the `test_hsm_azure_cloud_hsm_all` live test of the `azure_cloud_hsm_pkcs11_loader` crate. The task retries the test with a fresh daemon (`AZURE_CLOUD_HSM_TEST_ATTEMPTS`, default 3): the cluster occasionally advertises stale member addresses that make the 3-node quorum check fail transiently with `CKR_FUNCTION_FAILED`.

If you already have a configured Azure Cloud HSM client, run the live test directly:

```bash
AZURE_CLOUD_HSM_PKCS11_LIB=/opt/azurecloudhsm/lib64/libazcloudhsm_pkcs11.so \
  HSM_USER_PASSWORD='<cu_user>:<cu_password>' \
  HSM_SLOT_ID=<slot_id> \
  cargo test -p azure_cloud_hsm_pkcs11_loader --features azure_cloud_hsm,non-fips \
  -- --nocapture tests::test_hsm_azure_cloud_hsm_all --ignored --exact
```

See [`crate/hsm/azure_cloud_hsm/README.md`](https://github.com/Cosmian/kms/blob/develop/crate/hsm/azure_cloud_hsm/README.md) for the one-time runbook (GitHub Actions secrets, Private Link FQDN, `PO.crt`) used to provision the CI partition.
