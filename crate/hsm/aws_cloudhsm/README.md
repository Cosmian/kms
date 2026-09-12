# AWS CloudHSM

[TOC]

AWS CloudHSM is Amazon's dedicated, single-tenant HSM cluster service. It ships its own
PKCS#11 v2.40-compliant library (`libcloudhsm_pkcs11.so`), supporting AES, RSA, ECDSA, HMAC,
SHA and EdDSA(Ed25519) mechanisms.

This crate wires AWS CloudHSM into the generic `cosmian_kms_base_hsm::BaseHsm<P: HsmProvider>`
implementation, exactly like the Utimaco/Proteccio/Crypt2Pay/SmartCard-HSM loaders. **No
AWS-specific crypto/session code is required**: the AWS CloudHSM Crypto User (CU) login PIN is
simply the string `"<cu_username>:<cu_password>"` (see
<https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-pin.html>), which is passed
straight through as `--hsm-password`/`KMS_HSM_PASSWORD` with no code change.

> This is a different feature from AWS XKS (`crate/server/src/routes/aws_xks/`): XKS is AWS
> KMS calling into Cosmian as an external key store (reverse direction); this crate is Cosmian
> consuming AWS's own HSM hardware as one of its backend HSM vendors.

## Supported platforms

The AWS CloudHSM PKCS#11 library (Client SDK 5) supports:

- Amazon Linux 2 / Amazon Linux 2023
- RHEL 7, 8, 9, 10
- Ubuntu LTS releases
- `x86_64` and `arm64` architectures

**macOS is not supported** by AWS CloudHSM's client, unlike SoftHSM2 and SmartCard HSM.

## One-time cluster provisioning (for the persistent CI cluster)

Unlike SoftHSM2, there is no free/local AWS CloudHSM simulator. Provisioning a cluster takes
~15-20 minutes and costs ~$1.45/hr per HSM, so CI does **not** create/destroy a cluster per
run. Instead, CI connects to a **persistent, pre-provisioned, single-HSM cluster** — reached
over the network exactly like the existing Proteccio/Crypt2Pay hardware already used in CI
(fixed `concurrency.group`, single-tenant).

A maintainer with AWS console/CLI access must perform this **one-time** setup:

```bash
# 1. Create a VPC-attached cluster (adjust subnet IDs to your VPC)
aws cloudhsmv2 create-cluster --hsm-type hsm1.medium --subnet-ids subnet-xxxxxxxx \
  --tag-list Key=Name,Value=kms-ci-cloudhsm

# 2. Create the first HSM once the cluster is in `UNINITIALIZED` state
aws cloudhsmv2 create-hsm --cluster-id <cluster-id> --availability-zone <az>

# 3. Initialize the cluster: generate a CSR, sign it with your own CA (or a self-signed CA),
#    then activate the cluster. Follow:
#    https://docs.aws.amazon.com/cloudhsm/latest/userguide/initialize-cluster.html

# 4. Log in as the pre-configured Crypto Officer (CO) and create a dedicated CI Crypto User (CU):
#    (from a host with the CloudHSM client installed and configured against the cluster)
/opt/cloudhsm/bin/cloudhsm-cli interactive
> cluster user create --username kms-ci-cu --role crypto-user
```

Record the following as GitHub Actions repository secrets (never commit them):

| Secret                            | Value                                         |
| ---------------------------------- | ---------------------------------------------- |
| `KMS_CI_AWS_CLOUDHSM_CLUSTER_ID`   | the cluster ID created above                   |
| `KMS_CI_AWS_CLOUDHSM_CU_USERNAME`  | `kms-ci-cu`                                    |
| `KMS_CI_AWS_CLOUDHSM_CU_PASSWORD`  | the CU password set above                      |

The existing `KMS_CI_AWS_ACCESS_KEY_ID` / `KMS_CI_AWS_SECRET_ACCESS_KEY` / `KMS_CI_AWS_REGION`
secrets (already used elsewhere in `test_all.yml`) are reused to call
`aws cloudhsmv2 describe-clusters` and fetch the cluster's CA certificate chain at test time —
no separate secret is needed for the CA certificate itself. The IAM principal only needs the
read-only `cloudhsm:DescribeClusters` permission for this purpose.

## Running the CI test lane locally

```bash
mise run test:hsm-aws-cloudhsm --variant non-fips
```

This sources `.github/reusable_scripts/prepare_aws_cloudhsm.sh`, which installs the CloudHSM
PKCS#11 client package, fetches the cluster CA certificate via the AWS CLI, registers the
cluster with `configure-pkcs11 add-cluster`, and runs the full
`aws_cloudhsm_pkcs11_loader` test battery against it.

## Manual validation (without CI cluster access)

If you have your own AWS CloudHSM cluster and CU credentials, you can validate this crate
directly:

```bash
# Install the client (Ubuntu example, adjust for your distro/arch):
wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Bionic/cloudhsm-pkcs11_latest_u18.04_amd64.deb
sudo apt install ./cloudhsm-pkcs11_latest_u18.04_amd64.deb

# Register your cluster (requires its CA certificate chain, e.g. from
# `aws cloudhsmv2 describe-clusters` or your own customerCA.crt from cluster initialization):
sudo /opt/cloudhsm/bin/configure-pkcs11 add-cluster --cluster-id <cluster-id> \
  --hsm-ca-cert customerCA.crt

# Run the tests:
AWS_CLOUDHSM_PKCS11_LIB=/opt/cloudhsm/lib/libcloudhsm_pkcs11.so \
  HSM_USER_PASSWORD="<cu_username>:<cu_password>" \
  cargo test -p aws_cloudhsm_pkcs11_loader --features aws_cloudhsm,non-fips \
  -- --nocapture tests::test_hsm_aws_cloudhsm_all --ignored --exact
```

## Running the KMS server

Use the provided `kms.toml` file to run the KMS server with the AWS CloudHSM PKCS#11 library:

```toml
hsm_model    = "aws_cloudhsm"
hsm_slot     = [0]
hsm_password = ["<cu_username>:<cu_password>"]
```

From the KMS root directory, run:

```bash
AWS_CLOUDHSM_PKCS11_LIB=/opt/cloudhsm/lib/libcloudhsm_pkcs11.so \
  COSMIAN_KMS_CONF=crate/hsm/aws_cloudhsm/kms.toml cargo run --bin cosmian_kms --features non-fips
```
