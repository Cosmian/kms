# SoftHSM2

<!-- TOC -->
* [SoftHSM2](#softhsm2)
  * [Installing SoftHSM2](#installing-softhsm2)
    * [Running the KMS server](#running-the-kms-server)
<!-- TOC -->

## Installing SoftHSM2

Follow the instructions at https://github.com/softhsm/SoftHSMv2.

Set the SO and User PIN to 12345678 or update the `kms.toml` file accordingly.

### Running the KMS server

Use the provided `kms.toml` file to run the KMS server with the softhsm2 PKCS#11 library.

From the KMS root directory, run the following command:

```bash
COSMIAN_KMS_CONF=crate/hsm/softhsm2/kms.toml cargo run --bin cosmian_kms --features non-fips
```