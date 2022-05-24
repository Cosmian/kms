# KMS inside an enclave

## Pre-requisites

Compile and strip your kms binary. Example:

```sh
cargo build --release --features staging --bin cosmian_kms_server
```

Prepare the `data`, `public_data` and `scripts` directory on the SGX server:

```sh
./install.sh
```

Feel free to update ENV variables inside the `kms.manifest.template`.

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

For testing, start an Postgre SQL:

```sh
sudo docker run -d --rm --network=host --name postgre -e POSTGRES_DB=kms -e POSTGRES_USER=kms -e POSTGRES_PASSWORD=kms postgres:latest
```

Let's go:

```sh
sudo gramine-sgx ./kms
```

Enjoy ;)