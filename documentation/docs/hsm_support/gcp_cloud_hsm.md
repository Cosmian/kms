# GCP Cloud HSM

GCP Cloud HSM exposes Google Cloud KMS through Google's own PKCS#11 v2.40-compliant
compatibility library (`libkmsp11.so`), which is wired into the KMS's generic PKCS#11
implementation.

The integration is supported on **Linux (x86_64)**.

## Google client setup

Download and install Google's PKCS#11 library from the
[kms-integrations releases page](https://github.com/GoogleCloudPlatform/kms-integrations/releases)
(asset `libkmsp11-<version>-linux-amd64.tar.gz`).

The KMS expects the library to be installed at
`/usr/lib/x86_64-linux-gnu/libkmsp11.so` (the default installation path). Override it with the
`GCP_CLOUD_HSM_PKCS11_LIB` environment variable if your installation differs.

The library itself requires a YAML configuration file describing which Cloud KMS key ring(s) to
expose, set via the `KMS_PKCS11_CONFIG` environment variable:

```yaml
tokens:
  - key_ring: "projects/<project>/locations/<location>/keyRings/<key-ring>"
    label: "my key ring"
```

Authentication to GCP uses standard
[Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials)
— point `GOOGLE_APPLICATION_CREDENTIALS` at a service account key JSON file granted the
`cloudkms.cryptoKeys.*` / `cloudkms.cryptoKeyVersions.*` permissions listed in Google's
[PKCS #11 library user guide](https://github.com/GoogleCloudPlatform/kms-integrations/blob/master/kmsp11/docs/user_guide.md#authentication-and-authorization).

## Authentication

Google's library ignores the PKCS#11 login PIN value entirely (`C_Login` is a no-op per the
user guide above) — access is controlled solely by the service account credentials described
above. The KMS still requires a non-empty `hsm_password` value to open a PKCS#11 session; any
placeholder string works.

## KMS configuration

At least one slot and its corresponding (placeholder) PIN must be configured.

### Configuration via config file

When using the [TOML configuration file](../configuration/server_configuration_file.md#toml-configuration-file), enable HSM support by setting these parameters:

```toml
hsm_model = "gcp_cloud_hsm"
hsm_slot = [0]
hsm_password = ["<placeholder-pin>"]
```

> **_NOTE:_**  `hsm_slot` and `hsm_password` must always be arrays, even if only one slot is used.

### Configuration via command-line

HSM support can also be enabled with command-line arguments:

```shell
--hsm-model "gcp_cloud_hsm" \
--hsm-slot 0 --hsm-password "<placeholder-pin>"
```

The `hsm-model` parameter is the HSM model. Use `gcp_cloud_hsm`.

The `hsm-slot` and `hsm-password` parameters are the slot number and placeholder PIN of the HSM
slots used by the KMS. These options can be repeated to configure multiple slots (one per
configured token in the `KMS_PKCS11_CONFIG` YAML).

## Development and CI validation

See [`crate/hsm/gcp_cloud_hsm/README.md`](https://github.com/Cosmian/kms/blob/main/crate/hsm/gcp_cloud_hsm/README.md)
for the live test invocation. The CI `hsm-upstream` job matrix runs `mise run test:hsm-gcp-cloud-hsm`
against a persistent Cloud KMS HSM-tier key ring, downloading `libkmsp11.so` and provisioning the
service account credentials and PKCS#11 config file at runtime.
