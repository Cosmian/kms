# GCP Cloud HSM

GCP Cloud HSM exposes Google's Cloud KMS through the `libkmsp11.so` PKCS#11 compatibility library. This crate wires that library into the generic `BaseHsm` implementation.

## Configuration

Install Google's PKCS#11 library and configure its service account and Cloud KMS project according to Google's documentation. The KMS server accepts:

```toml
hsm_model = "gcp_cloud_hsm"
hsm_slot = [0]
hsm_password = ["<PKCS#11 PIN>"]
```

Override the library location with `GCP_CLOUD_HSM_PKCS11_LIB`. Configure the slot and PIN through `KMS_HSM_SLOT` and `KMS_HSM_PASSWORD` for the server, or `HSM_SLOT_ID` and `HSM_USER_PASSWORD` for the live loader test.

## Live test

The test requires Linux, `libkmsp11.so`, valid Google Cloud credentials, and a Cloud KMS HSM-tier key ring configured for the PKCS#11 library:

```bash
GCP_CLOUD_HSM_PKCS11_LIB=/path/to/libkmsp11.so \
HSM_SLOT_ID=0 \
HSM_USER_PASSWORD='<PKCS#11 PIN>' \
cargo test -p gcp_cloud_hsm_pkcs11_loader \
  --features gcp_cloud_hsm -- \
  --nocapture tests::test_hsm_gcp_cloud_hsm_all --ignored --exact
```

The live test is intentionally ignored by default because it requires external cloud infrastructure.
