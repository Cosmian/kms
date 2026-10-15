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

## Provision a test cluster

CloudHSM has no local simulator and each active HSM is billed by the hour.
Use a dedicated VPC, subnet, security group, and cluster for tests.

Create the cluster and its first HSM:

```bash
export AWS_REGION=<aws-region>
export AWS_SUBNET_ID=<private-subnet-id>
export AWS_AVAILABILITY_ZONE=<availability-zone>

aws cloudhsmv2 create-cluster \
  --region "$AWS_REGION" \
  --hsm-type hsm2m.medium \
  --subnet-ids "$AWS_SUBNET_ID" \
  --tag-list Key=Name,Value=kms-cloudhsm-test

export AWS_CLOUDHSM_CLUSTER_ID=<cluster-id>
aws cloudhsmv2 create-hsm \
  --region "$AWS_REGION" \
  --cluster-id "$AWS_CLOUDHSM_CLUSTER_ID" \
  --availability-zone "$AWS_AVAILABILITY_ZONE"
```

Wait for the cluster to reach `UNINITIALIZED`, then initialize and activate it by following
the [AWS cluster initialization procedure](https://docs.aws.amazon.com/cloudhsm/latest/userguide/initialize-cluster.html).
Keep the customer CA certificate used during initialization; it is required by
`configure-pkcs11`.

From a host with the CloudHSM client installed, create a dedicated Crypto User (CU) for the
test:

```text
/opt/cloudhsm/bin/cloudhsm-cli interactive
> cluster user create --username <cu-username> --role crypto-user
```

Do not reuse the Crypto Officer credentials in KMS or CI.

### Network access from GitHub-hosted runners

CloudHSM exposes private ENI addresses and does not provide a public endpoint.
For GitHub-hosted runners, provide an AWS Client VPN endpoint with:

1. a non-overlapping client CIDR;
2. certificate authentication and a valid server certificate;
3. a target-network association in the CloudHSM subnet or a routed subnet;
4. an authorization rule for the client CIDR;
5. a route to the CloudHSM subnet; and
6. security-group and network ACL rules allowing TCP `2223` from the VPN client range.

The test task expects the VPN profile in `AWS_CLOUDHSM_OVPN_CONF` when the HSM ENI is not
directly reachable.
Verify the route from the Linux test host before running PKCS#11 tests:

```bash
timeout 5 bash -c 'echo >/dev/tcp/<hsm-eni-ip>/2223'
```

Do not commit the VPN profile, CU password, customer CA, or certificate private keys.

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

## Tear down a test deployment

Create or verify a CloudHSM backup before removing the last HSM:

```bash
aws cloudhsmv2 create-backup \
  --region "$AWS_REGION" \
  --cluster-id "$AWS_CLOUDHSM_CLUSTER_ID"

aws cloudhsmv2 describe-backups \
  --region "$AWS_REGION" \
  --filters clusterIds="$AWS_CLOUDHSM_CLUSTER_ID"
```

After the backup reaches `READY`, remove the HSM. AWS creates a final backup when the last
HSM is removed; verify that backup and its retention policy before deleting anything else:

```bash
aws cloudhsmv2 delete-hsm \
  --region "$AWS_REGION" \
  --cluster-id "$AWS_CLOUDHSM_CLUSTER_ID" \
  --hsm-id <hsm-id>

aws cloudhsmv2 describe-clusters --region "$AWS_REGION"
aws cloudhsmv2 describe-backups \
  --region "$AWS_REGION" \
  --filters clusterIds="$AWS_CLOUDHSM_CLUSTER_ID"
```

Delete Client VPN target-network associations before deleting the endpoint:

```bash
aws ec2 disassociate-client-vpn-target-network \
  --client-vpn-endpoint-id <client-vpn-endpoint-id> \
  --association-id <association-id>

aws ec2 delete-client-vpn-endpoint \
  --client-vpn-endpoint-id <client-vpn-endpoint-id>
```

Keep the empty cluster only when restoring from its backup is required.
Delete it after confirming that required backups are retained elsewhere:

```bash
aws cloudhsmv2 delete-cluster \
  --region "$AWS_REGION" \
  --cluster-id "$AWS_CLOUDHSM_CLUSTER_ID"
```

CloudHSM backups remain billable storage; apply the retention policy deliberately and delete
expired backups when they are no longer needed.

## Development and CI validation

There is no free/local AWS CloudHSM simulator equivalent to SoftHSM2. See
[`crate/hsm/aws_cloudhsm/README.md`](https://github.com/Cosmian/kms/blob/main/crate/hsm/aws_cloudhsm/README.md)
for:

- the one-time runbook to provision a persistent AWS CloudHSM cluster for CI,
- the `mise run test:hsm-aws-cloudhsm` command used by the CI `hsm` job matrix, and
- a fully manual validation procedure for anyone without access to the CI cluster.
