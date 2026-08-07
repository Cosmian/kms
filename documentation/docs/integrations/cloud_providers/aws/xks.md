# Integration to AWS External Key Service (XKS)

## Background

AWS XKS (External Key Store) is a feature of AWS Key Management Service (AWS KMS) that allows you to use cryptographic keys stored in an external key management system with AWS KMS.
It enables you to maintain control over your keys while leveraging AWS services that integrate with AWS KMS.

**Source:** [AWS KMS XKS Proxy API Specification - Background](https://github.com/aws/aws-kms-xksproxy-api-spec/blob/main/xks_proxy_api_spec.md#background)

## Architecture

The Eviden KMS integrates to AWS XKS and proposes a novel architecture (dubbed *xksv2*) that solves the traditional XKS performance issues without compromising on security.

![xksv2 architecture diagram](./xksv2.drawio.svg)

The Eviden XKSv2 architecture is composed of the following components:

### Eviden Confidential KMS

This is the Confidential Key Management System, deployed as IaaS, in the customer AWS tenant.
It is responsible for managing the Key Encryption Keys (KEKs) wrapping the XKS keys in AWS KMS and for answering encryption and decryption requests from the AWS KMS.

To protect the KEKs, the Eviden KMS runs inside an Eviden VM on top of confidential computing machines. Eviden VM provides strong security and verifiability guarantees.

The Eviden KMS is deployed in AWS infrastructure, solving the XKS scaling problem, as it benefits from a stable high bandwidth network and can easily scale to reliably support large amount of transactions from the AWS KMS.

The Confidential KMS is available as a ready-to-deploy product from the [AWS Marketplace](https://aws.amazon.com/marketplace/search/results?searchTerms=COSMIAN+KMS).

### HSM

The HSM is responsible for storing the Master keys and securing the Eviden KMS keys. It is deployed in the customer premises or offered as a managed service by Atos. See the [HSM integration documentation](../../../hsm_support/introduction/index.md) for more details.

## Deployment

1. Deploy an Eviden KMS in your AWS tenant. You can find the product on the [AWS Marketplace](https://aws.amazon.com/marketplace/search/results?searchTerms=COSMIAN+KMS) and follow the deployment instructions in the product documentation.

2. Configure the KMS for use with AWS XKS by filling up the `aws_xks_config` section of the configuration file with the following values:

   ```toml
   [aws_xks_config]
   # set this to true
   aws_xks_enable = true
   # this is the region you Eviden KMS is deployed in
   aws_xks_region = "us-east-1"
   # keep this to this value
   aws_xks_service = "kms-xks-proxy"
   # used for sigv4. The values set here must match the values configured
   # when setting up the KMS as an external keystore for AWS KMS (see next step)
   aws_xks_sigv4_access_key_id = "AKIAIOSFODNN7EXAMPLE"
   aws_xks_sigv4_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
   ```

3. Configure the KMS to act as an External Key Store for AWS KMS. Follow the instructions in the [AWS documentation](https://docs.aws.amazon.com/kms/latest/developerguide/create-xks-keystore.html) to create an External Key Store.

4. Create an external key in AWS KMS and specify the key store created in the previous step as the key store for the key.

   ![Configure the key](./1_configure_key.png)
   ![Choose the external key](./2_choose_external_key.png)
   ![Review the key and create it](./7_review.png)

5. Authorize AWS principals to use the key.

   The KMS authenticates every XKS request from AWS KMS using the shared SigV4 credentials
   configured above (`aws_xks_sigv4_access_key_id` / `aws_xks_sigv4_secret_access_key`).
   This signature is the trust boundary, in line with AWS's model where the AWS key policy
   and IAM are the source of truth for which principals may use the key.

   XKS keys are used internally through a dedicated, reserved KMS service identity, so
   **any** AWS principal whose request is correctly signed can use the key.
   You do **not** need to create or maintain a per-principal (per-ARN) permission entry on
   the KMS for each IAM role, and the numerous or dynamic roles common with AWS SSO or
   Control Tower work without additional configuration.

   The keys remain owned by the KMS `default_username`, so you keep full administrative
   control over them (listing, revocation, destruction and export) from the CLI and the Web
   UI. The XKS service identity itself is granted only `Encrypt`, `Decrypt` and
   `GetAttributes`, so the XKS endpoints can never revoke, destroy or export key material.

   The `awsPrincipalArn` sent by AWS KMS is recorded in the KMS logs for auditing only and
   is never used as an authorization gate.

   Keys created by an earlier KMS version are updated automatically when the server starts,
   so no manual action is required when upgrading.
