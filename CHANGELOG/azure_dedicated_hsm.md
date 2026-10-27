## Features

### HSM
- Add Azure Cloud HSM support: `hsm_model = "azure_cloud_hsm"` (Linux x86_64) loads the Azure Cloud HSM PKCS#11 library (`/opt/azurecloudhsm/lib64/libazcloudhsm_pkcs11.so`, overridable with `AZURE_CLOUD_HSM_PKCS11_LIB`).

## Documentation

- Add the [Azure Cloud HSM](documentation/docs/hsm_support/azure_cloud_hsm.md) page to the HSM support section: client setup, Crypto User creation, slot-id discovery, KMS configuration, capabilities and limits.
