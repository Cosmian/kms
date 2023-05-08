# Cosmian KMS

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

## ERROR 2002 (HY000): Can't connect to server on 'gitlab-runner-1.ovh.cosmian.com' (115)

Run manually:

```bash
ssh cosmian@gitlab-runner-1.ovh.cosmian.com
sudo su -
su gitlab-runner
docker run -d --restart always -p 3306:3306 --name mariadb -e MYSQL_DATABASE=kms -e MYSQL_ROOT_PASSWORD=kms mariadb:latest
cd ~/data/
curl -k --data-binary @manifest.json https://gitlab-runner-1.ovh.cosmian.com:8080/enclave_manifest
```
