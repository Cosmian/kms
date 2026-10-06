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
export HSM_SLOT_ID=0
```

Select the backend in the KMS configuration:

```text
hsm_model = "azure_cloud_hsm"
```

The client configuration file, network addresses, partition, and credentials must be configured
with the Azure Cloud HSM client tools. The KMS passes the configured slot and password to PKCS#11
without embedding vendor-specific connection logic.

## Live test

The test requires Linux, a reachable Azure Cloud HSM partition, the Azure Cloud HSM PKCS#11
library, and credentials:

```bash
mise run test:hsm-azure-cloud-hsm --variant fips
```
