# SmartCard HSM

<!-- TOC -->
- [SmartCard HSM](#smartcard-hsm)
    - [Installing SmartCard HSM](#installing-smartcard-hsm)
    - [Running the KMS server](#running-the-kms-server)
<!-- TOC -->

## Installing SmartCard HSM

Follow the instructions at <https://github.com/CardContact/sc-hsm-embedded>.

## Running the KMS server

Use the provided `kms.toml` file to run the KMS server with the SmartCard PKCS#11 library.

From the KMS root directory, run the following command:

```bash
COSMIAN_KMS_CONF=crate/hsm/smartcardhsm/kms.toml cargo run --bin cosmian_kms --features non-fips
```
