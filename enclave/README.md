# KMS inside an enclave

Need `gramine 1.2`.

## Pre-requisites

Compile and strip your kms binary. Example:

```sh
cargo build --release --no-default-features --features staging --bin cosmian_kms_server
```

Prepare the `private_data` (mr enclave data), `public_data` (plain text data), `shared_data` (mr signer data) and `scripts` directory on the SGX server:

```sh
./install.sh
```

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

```
cargo build --release  --no-default-features --features staging  --bin cosmian_kms_cli
```

Then, on a fresh database:

```
KMS_CLI_CONF=kms-prod.json cosmian_kms_cli configure
```

Or in an already configured database:

```
KMS_CLI_CONF=kms-prod.json cosmian_kms_cli abe init 
```

Enjoy ;)