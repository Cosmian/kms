# Cosmian KMS

![Build status](https://github.com/Cosmian/kms/actions/workflows/ci.yml/badge.svg)

It's the implementation of the **Key Management Services** provided by _Cosmian_.

It is broken down into several binaries:

- A server (`cosmian_kms_server`) which is the KMS itself
- A CLI (`ckms`) to interact with this server

And also some libraries:

- `cosmian_kms_client` to query the server
- `cosmian_kms_utils` to create kmip requests for the crypto-systems designed by _Cosmian_
- `cosmian_kmip` which is an implementation of the kmip standard
- `cosmian_kms_pyo3` a KMS client in python.

**Please refer to the README of the inner directories to have more
information.**

The `enclave` directory contains all the requirements to run the KMS inside an Intel SGX enclave.

You can build a docker containing the KMS server as follow:

```sh
# Example with auth and https features
docker build . --network=host \
               --build-arg  \
               -t kms
```

The `delivery` directory contains all the requirements to proceed a KMS delivery based on a docker creation.

Find the public documentation of the KMS in the `documentation` directory.

## Quick start

From the root of the project, on your local machine, for developing:

```sh
cargo build --no-default-features
cargo test --no-default-features
```

## Releases

All releases can be found in the public URL [package.cosmian.com](https://package.cosmian.com/kms/).
