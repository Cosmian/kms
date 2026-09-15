# AWS CloudHSM vendor loader

## Features

### HSM

- Add AWS CloudHSM as a new supported HSM vendor: new `aws_cloudhsm_pkcs11_loader`
  crate (`crate/hsm/aws_cloudhsm`) wraps `cosmian_kms_base_hsm::BaseHsm` with an
  `AwsCloudHsmCapabilityProvider`, exactly mirroring the existing thin loaders for
  Utimaco/Proteccio/Crypt2Pay/SmartCard-HSM. No new crypto/session code was needed:
  the AWS CloudHSM PKCS#11 login PIN is the `"<cu_username>:<cu_password>"` string,
  a pure configuration convention supported by the existing `HsmConfig`
  ([#1159](https://github.com/Cosmian/kms/issues/1159))
- New `HsmModel::AwsCloudhsm` (`--hsm-model aws_cloudhsm`), gated to Linux
  (x86_64/ARM64 — AWS CloudHSM Client SDK 5 does not support macOS), wired through
  KMS instantiation, the config wizard (already generic over `HsmModel::VARIANTS`),
  and config file templates
- New CI end-to-end test lane against a persistent, pre-provisioned AWS CloudHSM
  cluster (mirrors how Proteccio/Crypt2Pay are tested against real, fixed hardware):
  `.github/reusable_scripts/prepare_aws_cloudhsm.sh` installs the CloudHSM PKCS#11
  client, fetches the cluster CA certificate via `aws cloudhsmv2 describe-clusters`
  (reusing the existing generic `KMS_CI_AWS_*` credentials), and registers the
  cluster; new mise task `test:hsm-aws-cloudhsm`; new `aws-cloudhsm` entry in the
  `hsm` CI matrix job, serialized via a dedicated `concurrency.group`. Requires
  three new repository secrets (`KMS_CI_AWS_CLOUDHSM_CLUSTER_ID`,
  `KMS_CI_AWS_CLOUDHSM_CU_USERNAME`, `KMS_CI_AWS_CLOUDHSM_CU_PASSWORD`) to be
  configured by a maintainer with AWS console access before the lane can run

## Documentation

- Document AWS CloudHSM setup, the `username:password` PIN convention, and
  `kms.toml` usage in a new `documentation/docs/hsm_support/aws_cloudhsm.md` page,
  linked from `SUMMARY.md` and `hsm_support/introduction/index.md`
- Add a manual cluster-provisioning runbook and validation procedure in
  `crate/hsm/aws_cloudhsm/README.md`
