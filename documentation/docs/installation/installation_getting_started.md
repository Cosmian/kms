Cosmian KMS can be installed on various platforms, including Docker, Ubuntu, Rocky Linux, macOS, and Windows.
It is prepackaged with an integrated web ui (except for Windows) that is available on the `/ui` path of the server.

The KMS is also available on the marketplaces of major cloud providers, prepackaged to run confidentially in a Cosmian VM.
Please check [this page](./marketplace_guide.md) for more information.

When installed using the options below, the KMS server will be automatically configured to run
using an SQLite database.
If you wish to change the database configuration, please refer to the [database guide](../database.md).

For high availability and scalability, refer to the [High Availability Guide](./high_availability_mode.md).

!!!info "Cosmian CLI"
    The Cosmian CLI lets you interact with the KMS from the command line.
    Install it from [Cosmian CLI](https://package.cosmian.com/cli/)
    and [configure it](../../cosmian_cli/index.md).

=== "Docker"

    Run the container as follows:

    ```sh
    docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest
    ```

    - The KMS UI is available at `http://localhost:9998/ui`.
    - The KMS REST API is available on `http://localhost:9998`,
    - The server stores its data inside the container in the `/root/cosmian-kms/sqlite-data` directory.

    A FIPS version is also available:

    ```sh
    docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms-fips:latest
    ```

    To persist data between restarts, mount the `/root/cosmian-kms/sqlite-data` path to a filesystem
    directory or a Docker volume:

    ```sh
    docker run --rm -p 9998:9998 \
    -v cosmian-kms:/root/cosmian-kms/sqlite-data \
    --name kms ghcr.io/cosmian/kms:latest
    ```

    A custom configuration file can be provided by mounting it in the container:

    ```sh
    docker run --rm -p 9998:9998 \
    -v cosmian-kms:/root/cosmian-kms/sqlite-data \
    -v /path/to/your/kms.toml:/etc/cosmian/kms.toml \
    --name kms ghcr.io/cosmian/kms:latest
    ```

=== "Debian 10 - Buster"

    Download the package and install it:

    ```sh
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/kms/5.10.0/debian10/cosmian-kms-server_5.10.0-1_amd64.deb
    sudo apt install ./cosmian-kms-server_5.10.0-1_amd64.deb
    sudo cosmian_kms --version
    ```

    Or install the FIPS version:

    ```sh
    wget https://package.cosmian.com/kms/5.10.0/debian10/cosmian-kms-server-fips_5.10.0-1_amd64.deb
    sudo apt install ./cosmian-kms-server-fips_5.10.0-1_amd64.deb
    sudo cosmian_kms --version
    ```

    A `cosmian_kms` service will be configured; the service file is located at `/etc/systemd/system/cosmian_kms.service`.
    To start the KMS, run:

    ```sh
    sudo systemctl start cosmian_kms
    ```

    - The server uses the configuration file located at `/etc/cosmian/kms.toml`.
    - The KMS UI is available at `http://localhost:9998/ui`.

=== "Ubuntu 22.04"

    Download the package and install it:

    ```sh
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/kms/5.10.0/ubuntu-22.04/cosmian-kms-server_5.10.0-1_amd64.deb
    sudo apt install ./cosmian-kms-server_5.10.0-1_amd64.deb
    sudo cosmian_kms --version
    ```

    Or install the FIPS version:

    ```sh
    wget https://package.cosmian.com/kms/5.10.0/ubuntu-22.04/cosmian-kms-server-fips_5.10.0-1_amd64.deb
    sudo apt install ./cosmian-kms-server-fips_5.10.0-1_amd64.deb
    sudo cosmian_kms --version
    ```

    A `cosmian_kms` service will be configured; the service file is located at `/etc/systemd/system/cosmian_kms.service`.
    To start the KMS, run:

    ```sh
    sudo systemctl start cosmian_kms
    ```

    - The server uses the configuration file located at `/etc/cosmian/kms.toml`.
    - The KMS UI is available at `http://localhost:9998/ui`.

=== "Ubuntu 24.04"

    Download the package and install it:

    ```sh
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/kms/5.10.0/ubuntu-24.04/cosmian-kms-server_5.10.0-1_amd64.deb
    sudo apt install ./cosmian-kms-server_5.10.0-1_amd64.deb
    sudo cosmian_kms --version
    ```

    Or install the FIPS version:

    ```sh
    wget https://package.cosmian.com/kms/5.10.0/ubuntu-24.04/cosmian-kms-server-fips_5.10.0-1_amd64.deb
    sudo apt install ./cosmian-kms-server-fips_5.10.0-1_amd64.deb
    sudo cosmian_kms --version
    ```

    A `cosmian_kms` service will be configured; the service file is located at `/etc/systemd/system/cosmian_kms.service`.
    To start the KMS, run:

    ```sh
    sudo systemctl start cosmian_kms
    ```

    - The server uses the configuration file located at `/etc/cosmian/kms.toml`.
    - The KMS UI is available at `http://localhost:9998/ui`.

=== "Rocky Linux 8"

    Download the package and install it:

    ```sh
    sudo dnf update && sudo dnf install -y wget
    wget https://package.cosmian.com/kms/5.10.0/rockylinux8/cosmian_kms_server-5.10.0-1.x86_64.rpm
    sudo dnf install ./cosmian_kms_server-5.10.0-1.x86_64.rpm
    sudo cosmian_kms --version
    ```

    To start the KMS, run:

    ```sh
    sudo systemctl start cosmian_kms
    ```

    - The server uses the configuration file located at `/etc/cosmian/kms.toml`.
    - The KMS UI is available at `http://localhost:9998/ui`.

=== "Rocky Linux 9"

    Download the package and install it:

    ```sh
    sudo dnf update && sudo dnf install -y wget
    wget https://package.cosmian.com/kms/5.10.0/rockylinux9/cosmian_kms_server-5.10.0-1.x86_64.rpm
    sudo dnf install ./cosmian_kms_server-5.10.0-1.x86_64.rpm
    sudo cosmian_kms --version
    ```

    To start the KMS, run:

    ```sh
    sudo systemctl start cosmian_kms
    ```

    - The server uses the configuration file located at `/etc/cosmian/kms.toml`.
    - The KMS UI is available at `http://localhost:9998/ui`.

=== "MacOS"

    On ARM MacOS, download the build archive and extract it:

    ```sh
    wget https://package.cosmian.com/kms/5.10.0/macos_arm-release.zip
    unzip macos_arm-release.zip
    cp ./macos_arm-release/Users/runner/work/kms/kms/target/aarch64-apple-darwin/release/cosmian_kms /usr/local/bin/
    chmod u+x /usr/local/bin/cosmian_kms
    cosmian_kms --version
    ```

    On Intel MacOS, download the build archive and extract it:

    ```sh
    wget https://package.cosmian.com/kms/5.10.0/macos_intel-release.zip
    unzip macos_intel-release.zip
    cp ./macos_intel-release/Users/runner/work/kms/kms/target/x86_64-apple-darwin/release/cosmian_kms /usr/local/bin/
    chmod u+x /usr/local/bin/cosmian_kms
    cosmian_kms --version
    ```

    The server uses the configuration file located at `/etc/cosmian/kms.toml`.

    NOTE: The MacOS version does NOT come with a web UI. It can be manually installed by copying the `dist` folder
    of a packaged Linux distribution to a folder and updating the `ui_index_html_folder` property of the `kms.toml`
    to point to it.

=== "Windows"

    On Windows, download the build archive:

    ```sh
     https://package.cosmian.com/kms/5.10.0/windows-release.zip
    ```

    Extract the cosmian_kms from:

    ```sh
    /windows-release/target/x86_64-pc-windows-msvc/release/cosmian_kms.exe
    ```

    Copy it to a folder in your PATH and run it:

    ```sh
    cosmian_kms --version
    ```
    The server uses the configuration file located at `C:\ProgramData\Cosmian\kms.toml`.
    if it is available. See the [server configuration](../server_configuration_file.md) for more information.

    NOTE: The Windows version does NOT come with a web UI. It can be manually installed by copying the `dist` folder
    of a packaged Linux distribution to a folder and updating the `ui_index_html_folder` property of the `kms.toml`
    to point to it.
