# Azure Dedicated HSM

Azure Dedicated HSM provides Thales Luna 7 Network HSM appliances. This crate exposes the
Thales Luna PKCS#11 client through the KMS `BaseHsm` implementation; Azure-specific network,
partition, and client certificate configuration remains in the Luna client configuration.

## Configuration

Install and configure the Thales Luna 7 PKCS#11 client on a Linux x86_64 host according to the
Azure Dedicated HSM and Thales documentation. The default library path is:

```text
/usr/lib/libCryptoki2_64.so
```

Override it when needed:

```bash
export AZURE_DEDICATED_HSM_PKCS11_LIB=/path/to/libCryptoki2_64.so
export HSM_USER_PASSWORD='<partition-password>'
export HSM_SLOT_ID=0
```

Select the backend in the KMS configuration:

```text
hsm_model = "azure_dedicated_hsm"
```

The partition name, Luna client certificates, network addresses, and HA settings must be
configured with the Thales Luna client tools. The KMS passes the configured slot and password to
PKCS#11 without embedding vendor-specific connection logic.

## Live test

The test requires Linux, a reachable Azure Dedicated HSM partition, the Thales PKCS#11 library,
and credentials:

```bash
mise run test:hsm-azure-dedicated-hsm --variant fips
```
