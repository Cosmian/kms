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

## Provision a test key ring

The integration uses Cloud KMS HSM-protected key versions; it does not provision a separate
Google Cloud HSM appliance.
Use a dedicated project or key ring for tests and verify that billing is enabled before creating
HSM key versions.

The provisioning identity needs permission to create key rings and keys.
The runtime service account needs the Cloud KMS permissions required by Google's PKCS#11 user
guide for the configured key ring.
Keep the service account key outside the repository.

Enable the required API if it is not already enabled:

```bash
export GCP_PROJECT=<gcp-project-id>
export GCP_LOCATION=<gcp-location>
export GCP_KEY_RING=kms-hsm-test

gcloud config set project "$GCP_PROJECT"
gcloud services enable cloudkms.googleapis.com
```

Create a dedicated HSM key ring and keys:

```bash
gcloud kms keyrings create "$GCP_KEY_RING" \
  --location "$GCP_LOCATION"

gcloud kms keys create kms-hsm-key \
  --location "$GCP_LOCATION" \
  --keyring "$GCP_KEY_RING" \
  --purpose encryption \
  --protection-level hsm

gcloud kms keys create kms-hsm-raw-key \
  --location "$GCP_LOCATION" \
  --keyring "$GCP_KEY_RING" \
  --purpose raw-encrypt-decrypt \
  --default-algorithm aes-256-gcm \
  --protection-level hsm
```

Grant the runtime identity access only to this key ring or its keys, then verify the protection
level before running tests:

```bash
gcloud kms keys describe kms-hsm-key \
  --location "$GCP_LOCATION" \
  --keyring "$GCP_KEY_RING" \
  --format='value(versionTemplate.protectionLevel)'

gcloud kms keys describe kms-hsm-raw-key \
  --location "$GCP_LOCATION" \
  --keyring "$GCP_KEY_RING" \
  --format='value(versionTemplate.protectionLevel)'
```

Both commands must return `HSM`.

## Configure the PKCS#11 library

Create the YAML file consumed by `libkmsp11.so`:

```yaml
tokens:
  - key_ring: "projects/<gcp-project-id>/locations/<gcp-location>/keyRings/<key-ring>"
    label: "gcp-cloud-hsm-test"
```

Set `KMS_PKCS11_CONFIG` to this file and set `GOOGLE_APPLICATION_CREDENTIALS` to the runtime
service account JSON on the Linux test host.
The `hsm_password` value remains a non-empty placeholder because Google's library treats
`C_Login` as a no-op.

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

The MISE task does not create GCP resources; it only checks the library and password variables
and runs the ignored loader test:

```bash
mise run test:hsm-gcp-cloud-hsm --variant non-fips
```

Run it from Linux with `GCP_CLOUD_HSM_PKCS11_LIB`, `KMS_PKCS11_CONFIG`,
`GOOGLE_APPLICATION_CREDENTIALS`, `HSM_SLOT_ID`, and `HSM_USER_PASSWORD` set.

## Tear down a test deployment

Cloud KMS charges for HSM key versions while they are `ENABLED`, `DISABLED`, or
`DESTROY_SCHEDULED`.
Schedule destruction immediately after the test:

```bash
for version in $(gcloud kms keys versions list \
  --key kms-hsm-raw-key \
  --location "$GCP_LOCATION" \
  --keyring "$GCP_KEY_RING" \
  --format='value(name.basename())'); do
  gcloud kms keys versions destroy "$version" \
    --key kms-hsm-raw-key \
    --location "$GCP_LOCATION" \
    --keyring "$GCP_KEY_RING"
done

gcloud kms keys versions destroy 1 \
  --key kms-hsm-key \
  --location "$GCP_LOCATION" \
  --keyring "$GCP_KEY_RING"
```

Google Cloud enforces a destruction grace period; the versions remain billable until the
scheduled destruction time.
After that time, verify that the versions are `DESTROYED`.

If a temporary Compute Engine VM was used to run the test, delete the VM and its test-only disk:

```bash
gcloud compute instances delete <test-vm> \
  --zone <zone> \
  --delete-disks=all
```

Do not delete shared key rings, service accounts, networks, or disks without confirming that no
other test or environment uses them.
