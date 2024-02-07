# Zero-trust KMS

The Cosmian KMS is designed to run in the cloud or any zero-trust environment by simply running it inside
a [Cosmian VM](https://docs.cosmian.com/compute/cosmian_vm/overview/)
and using the [Redis-Findex](./high_availability_mode.md) database to store the keys.

Cosmian provides pre-built Cosmian VM image with the KMS server and Redis-Findex database pre-installed for various
cloud providers.

A typical architecture for Google Workspace Client Side Encryption, with the KMS running on GCP, is shown below:

![google_cse_architecture](./images/google_cse.drawio.svg)
