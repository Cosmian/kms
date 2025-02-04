Cosmian KMS may be installed on a variety of platforms, including Docker, Ubuntu, RHEL, MacOS, and Windows.

It is also available on the major cloud providers marketplaces, prepackaged to run confidentially in a Cosmian VM.
Please check [this page](./marketplace_guide.md) for more information.

When installed using the options below, the KMS server will be automatically configured to run
using an SQLite database.
If you wish to change the database configuration, please refer to the [database guide](../database.md).

For high availability and scalability, please refer to the [high availability guide](./high_availability_mode.md).

!!!info "Cosmian CLI"
    The Cosmian CLI lets you interact with the KMS from the command line.
    Install it from [Cosmian CLI](https://package.cosmian.com/cli/)
    and [configure it](../../cosmian_cli/index.md).

=== "Docker"

    Run the container as follows:

    ```sh
    docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest
    ```

    The KMS will be available on `http://localhost:9998`, and the server will store its data inside the
    container in the `/root/cosmian-kms/sqlite-data` directory.

    FIPS version is also available:

    ```sh
    docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms-fips:latest
    ```

    To persist data between restarts, map the `/root/cosmian-kms/sqlite-data` path to a filesystem
    directory or a Docker volume, e.g. with a volume named `cosmian-kms`:

    ```sh
    docker run --rm -p 9998:9998 \
    -v cosmian-kms:/root/cosmian-kms/sqlite-data \
    --name kms ghcr.io/cosmian/kms:latest
    ```

=== "Ubuntu 20.04"

    Download package and install it:

    ```sh
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/kms/4.22.0/ubuntu-20.04/cosmian-kms-server_4.22.0-1_amd64.deb
    sudo apt install ./cosmian-kms-server_4.22.0-1_amd64.deb
    cosmian_kms --version
    ```

    Or install the FIPS version:

    ```sh
    wget https://package.cosmian.com/kms/4.22.0/ubuntu-20.04/cosmian-kms-server-fips_4.22.0-1_amd64.deb
    sudo apt install ./cosmian-kms-server-fips_4.22.0-1_amd64.deb
    cosmian_kms --version
    ```

    A `cosmian_kms` service will be configured; the service file is located at `/etc/systemd/system/cosmian_kms.service`.
    The server will use a configuration file located at `/etc/cosmian_kms/kms.toml`.

    To start the KMS, run:

    ```sh
    sudo systemctl start cosmian_kms
    ```

=== "Ubuntu 22.04"

    Download package and install it:

    ```sh
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/kms/4.22.0/ubuntu-22.04/cosmian-kms-server_4.22.0-1_amd64.deb
    sudo apt install ./cosmian-kms-server_4.22.0-1_amd64.deb
    cosmian_kms --version
    ```

    Or install the FIPS version:

    ```sh
    wget https://package.cosmian.com/kms/4.22.0/ubuntu-22.04/cosmian-kms-server-fips_4.22.0-1_amd64.deb
    sudo apt install ./cosmian-kms-server-fips_4.22.0-1_amd64.deb
    cosmian_kms --version
    ```

    A `cosmian_kms` service will be configured; the service file is located at `/etc/systemd/system/cosmian_kms.service`.
    The server will use a configuration file located at `/etc/cosmian_kms/kms.toml`.

    To start the KMS, run:

    ```sh
    sudo systemctl start cosmian_kms
    ```

=== "Ubuntu 24.04"

    Download package and install it:

    ```sh
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/kms/4.22.0/ubuntu-24.04/cosmian-kms-server_4.22.0-1_amd64.deb
    sudo apt install ./cosmian-kms-server_4.22.0-1_amd64.deb
    cosmian_kms --version
    ```

    Or install the FIPS version:

    ```sh
    wget https://package.cosmian.com/kms/4.22.0/ubuntu-24.04/cosmian-kms-server-fips_4.22.0-1_amd64.deb
    sudo apt install ./cosmian-kms-server-fips_4.22.0-1_amd64.deb
    cosmian_kms --version
    ```

    A `cosmian_kms` service will be configured; the service file is located at `/etc/systemd/system/cosmian_kms.service`.
    The server will use a configuration file located at `/etc/cosmian_kms/kms.toml`.

    To start the KMS, run:

    ```sh
    sudo systemctl start cosmian_kms
    ```

=== "RHEL 9"

    Download package and install it:

    ```sh
    sudo dnf update && dnf install -y wget
    wget https://package.cosmian.com/kms/4.22.0/rhel9/cosmian_kms_server-4.22.0-1.x86_64.rpm
    sudo dnf install ./cosmian_kms_server-4.22.0-1.x86_64.rpm
    cosmian_kms --version
    ```

=== "MacOS"

    On ARM MacOS, download the build archive and extract it:

    ```sh
    wget https://package.cosmian.com/kms/4.22.0/macos_arm-release.zip
    unzip macos_arm-release.zip
    cp ./macos_arm-release/Users/runner/work/kms/kms/target/aarch64-apple-darwin/release/cosmian_kms /usr/local/bin/
    chmod u+x /usr/local/bin/cosmian_kms
    cosmian_kms --version
    ```

    On Intel MacOS, download the build archive and extract it:

    ```sh
    wget https://package.cosmian.com/kms/4.22.0/macos_intel-release.zip
    unzip macos_intel-release.zip
    cp ./macos_intel-release/Users/runner/work/kms/kms/target/x86_64-apple-darwin/release/cosmian_kms /usr/local/bin/
    chmod u+x /usr/local/bin/cosmian_kms
    cosmian_kms --version
    ```

=== "Windows"

    On Windows, download the build archive:

    ```sh
     https://package.cosmian.com/kms/4.22.0/windows-release.zip
    ```

    Extract the cosmian_kms from:

    ```sh
    /windows-release/target/x86_64-pc-windows-msvc/release/cosmian_kms.exe
    ```

    Copy it to a folder in your PATH and run it:

    ```sh
    cosmian_kms --version
    ```
