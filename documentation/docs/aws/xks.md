AWS External Key Service (XKS) lets customers externalize the management of their AWS keys in a Key Management System under their control.

The Cosmian KMS integrates to AWS XKS and proposes a novel architecture (dubbed xksv2) that solves the traditional XKS performance issues without compromising on security.

![xksv2 architecture diagram](./xksv2.drawio.svg)

## Architecture

The Cosmian XKSv2 architecture is composed of the following components:

### Cosmian Confidential KMS

This is the Confidential Key Management System, deployed as IaaS, in the customer AWS tenant.

It is responsible for managing the Key Encryption Keys (KEKs) wrapping the XKS keys in AWS KMS and for answering encryption and decryption requests from the AWS KMS.

To protect the KEKs, the Cosmian KMS runs inside a Cosmian VM on top of confidential computing machines. Cosmian VM provides strong security and verifiability guarantees.

The Cosmian KMS is deployed in AWS infrastructure, solving the XKS scaling problem, as it benefits from a stable high bandwidth network and can easily scale to reliably support large amount of transactions from the AWS KMS.

The Confidential KMS is available as a ready-to-deploy product from the AWS Marketplace.

### HSM



