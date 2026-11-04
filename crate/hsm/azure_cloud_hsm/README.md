# Azure Cloud HSM

Azure Cloud HSM exposes a PKCS#11 library for applications running in Azure. This crate exposes
that library through the KMS `BaseHsm` implementation; network and client configuration remains
in the Azure Cloud HSM client configuration.

## Configuration

Install and configure the Azure Cloud HSM client on a Linux x86_64 host according to the
[Azure Cloud HSM PKCS#11 Integration Guide](https://github.com/microsoft/MicrosoftAzureCloudHSM/blob/main/IntegrationGuides/Azure%20Cloud%20HSM%20PKCS11%20Integration%20Guide.pdf).
The default library path is:

```text
/opt/azurecloudhsm/lib64/libazcloudhsm_pkcs11.so
```

Override it when needed:

```bash
export AZURE_CLOUD_HSM_PKCS11_LIB=/path/to/libazcloudhsm_pkcs11.so
export HSM_USER_PASSWORD='<user>:<password>'
export HSM_SLOT_ID=<slot_id>
```

`<slot_id>` is the PKCS#11 slot id for the partition, **not** the position of the slot in
`C_GetSlotList`. Discover it with:

```bash
pkcs11-tool --module /opt/azurecloudhsm/lib64/libazcloudhsm_pkcs11.so --list-slots
```

`pkcs11-tool` prints each entry as `Slot <index> (0x<slot_id>)`; use the hexadecimal value in
parentheses (e.g. `Slot 0 (0x1)` means `HSM_SLOT_ID=1`). Passing the list index instead of the
real slot id fails with `CKR_SLOT_ID_INVALID`.

Select the backend in the KMS configuration:

```text
hsm_model = "azure_cloud_hsm"
```

The client configuration file, network addresses, partition, and credentials must be configured
with the Azure Cloud HSM client tools. The KMS passes the configured slot and password to PKCS#11
without embedding vendor-specific connection logic.

## One-time partition provisioning (for the persistent CI partition)

Like AWS CloudHSM, CI connects to a **persistent, pre-provisioned Azure Cloud HSM partition**
rather than creating/destroying one per run. A maintainer with Azure portal/CLI access must
perform this **one-time** setup, following the
[Integration Guide](https://github.com/microsoft/MicrosoftAzureCloudHSM/blob/main/IntegrationGuides/Azure%20Cloud%20HSM%20PKCS11%20Integration%20Guide.pdf):

1. Deploy and initialize an Azure Cloud HSM resource; note the partition owner certificate
   (`PO.crt`) and the `hsm1.chsm-<resourcename>-<uniquestring>.privatelink.cloudhsm.azure.net`
   Private Link FQDN.
2. Log in as the Crypto Officer (CO) with `azcloudhsm_mgmt_util` and create a dedicated CI
   Crypto User (CU):

   ```bash
   sudo ./azcloudhsm_mgmt_util ./azcloudhsm_resource.cfg
   loginHSM CO <co_user> <co_password>
   createUser CU kms-ci-cu <cu_password>
   ```

Record the following as GitHub Actions repository secrets (never commit them):

| Secret                               | Value                                                    |
| ------------------------------------- | ----------------------------------------------------------- |
| `KMS_CI_AZURE_CLOUD_HSM_PO_CERT`      | contents of `PO.crt`                                       |
| `KMS_CI_AZURE_CLOUD_HSM_HOSTNAME`     | the Private Link FQDN (`hsm1.chsm-...privatelink...`)       |
| `KMS_CI_AZURE_CLOUD_HSM_USER_PASSWORD`| `kms-ci-cu:<cu_password>`                                  |
| `KMS_CI_AZURE_CLOUD_HSM_SLOT_ID`      | the PKCS#11 slot id for the partition                      |
| `KMS_CI_AZURE_CLOUD_HSM_HSM_IP`       | (optional) the HSM's private IP, if the runner cannot resolve the Private Link FQDN |
| `KMS_CI_AZURE_CLOUD_HSM_OVPN_CONF`    | (optional) an OpenVPN profile routing to that private IP, if not otherwise reachable |

## Running the CI test lane locally

```bash
mise run test:hsm-azure-cloud-hsm --variant non-fips
```

This sources `.github/reusable_scripts/prepare_azure_cloudhsm.sh`, which installs the Azure
Cloud HSM Client SDK, writes `PO.crt` and `azcloudhsm_resource.cfg`, opens a VPN tunnel to the
partition if it is not directly reachable, and starts the `azcloudhsm_client` daemon before
running the `azure_cloud_hsm_pkcs11_loader` test suite.

The task retries the live test (`AZURE_CLOUD_HSM_TEST_ATTEMPTS`, default 3) with a fresh
`azcloudhsm_client` restart between attempts: the cluster's own cluster-info broadcast
occasionally advertises stale, non-VNet member addresses that the client cannot reach, which
makes the 3-node quorum check for key generation fail transiently (`CKR_FUNCTION_FAILED`)
even though all current nodes are healthy. A fresh daemon reliably clears that stale view.

## Manual validation (without CI partition access)

If you already have a configured Azure Cloud HSM client (see Configuration above), bypass the
prepare script and call the test directly:

```bash
AZURE_CLOUD_HSM_PKCS11_LIB=/opt/azurecloudhsm/lib64/libazcloudhsm_pkcs11.so \
  HSM_USER_PASSWORD='<user>:<password>' \
  HSM_SLOT_ID=<slot_id> \
  cargo test -p azure_cloud_hsm_pkcs11_loader --features azure_cloud_hsm,non-fips \
  -- --nocapture tests::test_hsm_azure_cloud_hsm_all --ignored --exact
```

See [Configuration](#configuration) above to discover `<slot_id>` with `pkcs11-tool`.

## Live test

The test requires Linux, a reachable Azure Cloud HSM partition, the Azure Cloud HSM PKCS#11
library, and credentials:

```bash
mise run test:hsm-azure-cloud-hsm --variant fips
```
