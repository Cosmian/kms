The single server mode uses an embedded SQLite database stored on a filesystem and therefore does
not require access to an external database.

Although it does not provide high availability through redundancy, this configuration is suitable
for production and serving millions of cryptographic objects. The server will concurrently serve
requests on as many threads as available cores to the docker container.

This configuration also supports user encrypted databases, a secure way to store cryptographic
objects since database keys are provisioned on every request, and no database key is stored server
side. To offer a fully secure solution suitable for deployment in a zero-trust environment such as
the cloud, TLS must be enabled on the server, and the memory of the KMS server must also be
protected during operation by running the server inside an enclave. Ask Cosmian for details.

### Quick start

To run in single server mode, using the defaults and a SQLite database will be created. Otherwise,
the database can be configured using classic databases such as PostgreSQL, MySQL or MariaDB or the Cosmian custom protected Redis, please follow [the database configuration page]](./database.md).

=== "Ubuntu 20.04"

    Download package and install it:

    ```console title="On local machine"
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/kms/4.20.1/ubuntu-20.04/cosmian-kms-server_4.20.1-1_amd64.deb
    sudo apt install ./cosmian-kms-server_4.20.1-1_amd64.deb
    cosmian --version
    ```

    Or install the FIPS version:

    ```console title="FIPS version"
    wget https://package.cosmian.com/kms/4.20.1/ubuntu-20.04/cosmian-kms-server-fips_4.20.1-1_amd64.deb
    sudo apt install ./cosmian-kms-server-fips_4.20.1-1_amd64.deb
    cosmian --version
    ```

=== "Ubuntu 22.04"

    Download package and install it:

    ```console title="On local machine"
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/kms/4.20.1/ubuntu-22.04/cosmian-kms-server_4.20.1-1_amd64.deb
    sudo apt install ./cosmian-kms-server_4.20.1-1_amd64.deb
    cosmian --version
    ```

    Or install the FIPS version:

    ```console title="FIPS version"
    wget https://package.cosmian.com/kms/4.20.1/ubuntu-22.04/cosmian-kms-server-fips_4.20.1-1_amd64.deb
    sudo apt install ./cosmian-kms-server-fips_4.20.1-1_amd64.deb
    cosmian --version
    ```

=== "Ubuntu 24.04"

    Download package and install it:

    ```console title="On local machine"
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/kms/4.20.1/ubuntu-24.04/cosmian-kms-server_4.20.1-1_amd64.deb
    sudo apt install ./cosmian-kms-server_4.20.1-1_amd64.deb
    cosmian --version
    ```

    Or install the FIPS version:

    ```console title="FIPS version"
    wget https://package.cosmian.com/kms/4.20.1/ubuntu-24.04/cosmian-kms-server-fips_4.20.1-1_amd64.deb
    sudo apt install ./cosmian-kms-server-fips_4.20.1-1_amd64.deb
    cosmian --version
    ```

=== "RHEL 9"

    Download package and install it:

    ```console title="On local machine"
    sudo dnf update && dnf install -y wget
    wget https://package.cosmian.com/kms/4.20.1/rhel9/cosmian_kms_server-4.20.1-1.x86_64.rpm
    sudo dnf install ./cosmian_kms_server-4.20.1-1.x86_64.rpm
    cosmian --version
    ```

=== "MacOS"

    On ARM MacOS, download the build archive and extract it:

    ```console title="On local machine"
    wget https://package.cosmian.com/kms/4.20.1/macos_arm-release.zip
    unzip macos_arm-release.zip
    cp /macos_arm-release/Users/runner/work/kms/kms/target/aarch64-apple-darwin/release/cosmian /usr/local/bin/
    chmod u+x /usr/local/bin/cosmian
    cosmian --version
    ```

    On Intel MacOS, download the build archive and extract it:

    ```console title="On local machine"
    wget https://package.cosmian.com/kms/4.20.1/macos_intel-release.zip
    unzip macos_intel-release.zip
    cp /macos_intel-release/Users/runner/work/kms/kms/target/x86_64-apple-darwin/release/cosmian /usr/local/bin/
    chmod u+x /usr/local/bin/cosmian
    cosmian --version
    ```

=== "Windows"

    On Windows, download the build archive:

    ```console title="Build archive"
     https://package.cosmian.com/kms/4.20.1/windows-release.zip
    ```

    Extract the cosmian from:

    ```console title="cosmian for Windows"
    /windows-release/target/x86_64-pc-windows-msvc/release/cosmian.exe
    ```

    Copy it to a folder in your PATH and run it:

    ```console title="On local machine"
    cosmian --version
    ```

=== "Docker"

    Run the container as follows:

    ```sh
    docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:4.20.1
    ```

    The KMS will be available on `http://localhost:9998`, and the server will store its data inside the
    container in the `/root/cosmian-kms/sqlite-data` directory.

    To persist data between restarts, map the `/root/cosmian-kms/sqlite-data` path to a filesystem
    directory or a Docker volume, e.g. with a volume named `cosmian-kms`:

    ```sh
    docker run --rm -p 9998:9998 \
    -v cosmian-kms:/root/cosmian-kms/sqlite-data \
    --name kms ghcr.io/cosmian/kms:4.20.1
    ```

### Using client-side encrypted databases

To start the KMS server with a client-side encrypted SQLite databases, pass the
`--database-type=sqlite-enc` on start, e.g.

```sh
docker run --rm -p 9998:9998 \
  -v cosmian-kms:/root/cosmian-kms/sqlite-data \
  --name kms ghcr.io/cosmian/kms:4.20.1 \
  --database-type=sqlite-enc
```

!!! important "Important: encrypted databases must be created first"

    Before using an encrypted database, you must create it by calling the `POST /new_database` endpoint.
    The call will return a secret

    === "cosmian"

        ```sh
        cosmian kms new-database
        ```

    === "curl"

        ```sh
        ➜ curl -X POST https://my-server:9998/new_database
        "eyJncm91cF9pZCI6MzE0ODQ3NTQzOTU4OTM2Mjk5OTY2ODU4MTY1NzE0MTk0MjU5NjUyLCJrZXkiOiIzZDAyNzg3YjUyZGY5OTYzNGNkOTVmM2QxODEyNDk4YTRiZWU1Nzc1NmM5NDI0NjdhZDI5ZTYxZjFmMmM0OWViIn0="%
        ```
        The secret is the value between the quotes `""`.

    Warning:

        - This secret is only displayed **once** and is **not stored** anywhere on the server.
        - Each call to `new_database` will create a **new additional** database. It will not return the secret of the last created database, and it will not overwrite the last created database.

Once an encrypted database is created, the secret must be passed in every subsequent query to the
KMS server.
Passing the correct secret "auto-selects" the correct encrypted database: multiple encrypted
databases can be used concurrently on the same KMS server.

=== "cosmian"

    The secret must be set in `database_secret` property of the CLI `cosmian.json` configuration file.

        ```toml
        [kms_config.http_config]
        server_url = "http://127.0.0.1:9990"
        access_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6Ik...yaJbDDql3A"
        database_secret = "eyJncm91cF9pZCI6MTI5N...MWIwYjE5ZmNlN2U3In0="
        ```

=== "curl"

    The secret must be passed using a `DatabaseSecret` HTTP header, e.g.

    ```sh
        curl \
        -H "DatabaseSecret: eyJncm91cF9pZCI6MzE0ODQ3NTQzOTU4OTM2Mjk5OTY2ODU4MTY1NzE0MTk0MjU5NjUyLCJrZXkiOiIzZDAyNzg3YjUyZGY5OTYzNGNkOTVmM2QxODEyNDk4YTRiZWU1Nzc1NmM5NDI0NjdhZDI5ZTYxZjFmMmM0OWViIn0=" \
        http://localhost:9998/objects/owned
    ```
