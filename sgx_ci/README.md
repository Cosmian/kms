# KMS inside an enclave

Need `gramine 1.5`.

## Pre-requisites

Compile and strip your kms binary. Example:

```sh
cargo build --release --no-default-features --bin cosmian_kms_server
```

Create the `private_data` (mr enclave data), `public_data` (plain text data) and `scripts` directory on the SGX server.

Feel free to update `ENV` variables inside the `kms.manifest.template`.

Send the binary and the content of this folder to your SGX server.

```sh
scp -r . cosmian@<IP>:kms/
scp target/debug/cosmian_kms_server cosmian@<IP>:kms/scripts/server
```

On the SGX server, generate keys for the enclave:

```sh
sudo openssl genrsa -3 -out /opt/cosmian-internal/cosmian-signer-key.pem 3072
sudo chown cosmian:cosmian /opt/cosmian-internal/cosmian-signer-key.pem
sudo chmod 644 /opt/cosmian-internal/cosmian-signer-key.pem
```

## Seal the SGX manifest

```sh
make clean && make SGX=1 DEBUG=0
```

You need to do that every time your KMS binary changed.

## Start Gramine / The enclave

Let's go:

```sh
sudo gramine-sgx ./kms
```

If you choose, Postgre SQL as kms database, you can start on as follow:

```sh
sudo docker run -d --rm --network=host --name postgre -e POSTGRES_DB=kms -e POSTGRES_USER=kms -e POSTGRES_PASSWORD=kms postgres:latest
```

## Testing

You can query the KMS with the CLI.

Make sure you have compiled it with the same feature than the server. For example with the `staging` feature:

```sh
cargo build --release  --no-default-features --features insecure  --bin ckms
```

Then:

```sh
KMS_CLI_CONF=kms-test.json ckms bootstrap-start --sqlite-path private_data/  --database-type sqlite
KMS_CLI_CONF=kms-test.json ckms sym keys create
```

Enjoy ;)

## Dockerization

### Build

On a **non-sgx** machine, from the root of the project:

```sh
sudo docker build -f sgx/Dockerfile.sgx -t enclave-kms .
```

### Run

On an **sgx** machine:

```sh
# Plain text directory
mkdir -p public_data/
mkdir -p private_data/

# Start the docker
sudo docker run \
    --device /dev/sgx_enclave \
    --device /dev/sgx_provision \
    -v /var/run/aesmd:/var/run/aesmd/ \
    -v /opt/cosmian-internal:/opt/cosmian-internal \
    -v $PWD/public_data:/root/public_data \
    -v $PWD/private_data:/root/private_data \
    -p80:80 \
    -p9998:9998 \
    -it enclave-kms
```

### Emulate

The KMS docker is openly published so that KMS users can check the integrity of the running code against the open-source code on [*Cosmian* Github](https://github.com/Cosmian).

To do so, the user needs to compute the `MR_ENCLAVE` and needs to compare it to the one returned by the running KMS.
Using `--emulation` param, the KMS docker can locally compute `MR_ENCLAVE`. Just start it as follow from any kind of machine:

```sh
sudo docker run \
    -v public_data:/root/public_data \
    -it enclave-kms --emulation
```

The `MR_ENCLAVE` can be read from the output of the docker itself.

```sh
Measurement:
    c8e0ac76ee1b9416e53890677cbbce8a5f1d8bf2f1c7ab208c1e0efa56e8cea2

Attributes:
    mr_enclave: c8e0ac76ee1b9416e53890677cbbce8a5f1d8bf2f1c7ab208c1e0efa56e8cea2
```

The `public_data` directory contains the compiled manifest with all trusted files hashes.

**Note**: the `MR_SIGNER` should be ignored. It is obviously wrong because we don't use cosmian public key to generate the enclave in that case.
