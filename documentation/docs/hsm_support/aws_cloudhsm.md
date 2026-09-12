# AWS CloudHSM

AWS CloudHSM is Amazon's dedicated, single-tenant HSM cluster service. It ships its own
PKCS#11 v2.40-compliant library (`libcloudhsm_pkcs11.so`), supporting AES, RSA, ECDSA, HMAC,
SHA and EdDSA(Ed25519) mechanisms.

The integration is supported on **Linux (x86_64 and arm64)** — AWS CloudHSM's PKCS#11 client
does not support macOS.

> This is a different feature from [AWS XKS](../integrations/cloud_providers/aws/xks.md): XKS is
> AWS KMS calling into Cosmian as an external key store (reverse direction); this integration
> is Cosmian consuming AWS's own HSM hardware as one of its backend HSM vendors — the same
> direction as the Utimaco, Proteccio, Crypt2Pay, and SmartCard HSM integrations.

## AWS CloudHSM client setup

To use AWS CloudHSM with the KMS, install the **AWS CloudHSM Client SDK 5 PKCS#11 library**
following the [AWS documentation](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library-install.html).

The KMS expects the library to be installed at `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so`
(the default installation path). Override it with the `AWS_CLOUDHSM_PKCS11_LIB` environment
variable if your installation differs.

Register your cluster with the client using `configure-pkcs11`:

```shell
sudo /opt/cloudhsm/bin/configure-pkcs11 add-cluster \
  --cluster-id <cluster-id> \
  --hsm-ca-cert customerCA.crt
```

## Authentication

The PKCS#11 login PIN expected by AWS CloudHSM for a Crypto User (CU) is the string
`"<cu_username>:<cu_password>"` (see the
[AWS documentation](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-pin.html)).
Pass this combined string directly as the KMS `hsm_password` value — no other configuration
is required.

## KMS configuration

At least one slot and its corresponding PIN must be configured.

### Configuration via config file

When using the [TOML configuration file](../configuration/server_configuration_file.md#toml-configuration-file), enable HSM support by setting these parameters:

```toml
hsm_model = "aws_cloudhsm"
hsm_admin = "<HSM_ADMIN_USERNAME>" # defaults to "admin"
hsm_slot = [0]
hsm_password = ["<cu_username>:<cu_password>"]
```

> **_NOTE:_**  `hsm_slot` and `hsm_password` must always be arrays, even if only one slot is used.
>
> The order of the passwords must match the order of the slots in the `hsm_slot` array.

### Configuration via command-line

HSM support can also be enabled with command-line arguments:

```shell
--hsm-model "aws_cloudhsm" \
--hsm-admin "<HSM_ADMIN_USERNAME>" \
--hsm-slot 0 --hsm-password "<cu_username>:<cu_password>"
```

The `hsm-model` parameter is the HSM model. Use `aws_cloudhsm`.

The `hsm-admin` parameter is the username of the HSM administrator.
The HSM administrator is the only user who can create objects on the HSM via the KMIP `Create` operation
and delegate other operations to other users.

The `hsm-slot` and `hsm-password` parameters are the slot number and CU login PIN of the HSM
slots used by the KMS. These options can be repeated to configure multiple slots.

> **_NOTE:_** To list available slots, run:
>
> ```shell
> pkcs11-tool --module /opt/cloudhsm/lib/libcloudhsm_pkcs11.so --list-slots
> ```

## Development and CI validation

There is no free/local AWS CloudHSM simulator equivalent to SoftHSM2. See
[`crate/hsm/aws_cloudhsm/README.md`](https://github.com/Cosmian/kms/blob/main/crate/hsm/aws_cloudhsm/README.md)
for:

- the one-time runbook to provision a persistent AWS CloudHSM cluster for CI,
- the `mise run test:hsm-aws-cloudhsm` command used by the CI `hsm` job matrix, and
- a fully manual validation procedure for anyone without access to the CI cluster.
