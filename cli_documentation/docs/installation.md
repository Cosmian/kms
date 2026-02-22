=== "Debian 10 - buster"

    Download package and install it:

    ```console title="On local machine"
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/cli/5.16.1/debian10/cosmian-cli_5.16.1-1_amd64.deb
    sudo apt install ./cosmian-cli_5.16.1-1_amd64.deb
    cosmian --version
    ```

=== "Ubuntu 22.04"

    Download package and install it:

    ```console title="On local machine"
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/cli/5.16.1/ubuntu-22.04/cosmian-cli_5.16.1-1_amd64.deb
    sudo apt install ./cosmian-cli_5.16.1-1_amd64.deb
    cosmian --version
    ```

=== "Ubuntu 24.04"

    Download package and install it:

    ```console title="On local machine"
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/cli/5.16.1/ubuntu-24.04/cosmian-cli_5.16.1-1_amd64.deb
    sudo apt install ./cosmian-cli_5.16.1-1_amd64.deb
    cosmian --version
    ```

=== "Rocky Linux 8"

    Download package and install it:

    ```console title="On local machine"
    sudo dnf update && sudo dnf install -y wget
    wget https://package.cosmian.com/cli/5.16.1/rockylinux8/cosmian_cli-5.16.1-1.x86_64.rpm
    sudo dnf install ./cosmian_cli-5.16.1-1.x86_64.rpm
    cosmian --version
    ```

=== "Rocky Linux 9"

    Download package and install it:

    ```console title="On local machine"
    sudo dnf update && sudo dnf install -y wget
    wget https://package.cosmian.com/cli/5.16.1/rockylinux9/cosmian_cli-5.16.1-1.x86_64.rpm
    sudo dnf install ./cosmian_cli-5.16.1-1.x86_64.rpm
    cosmian --version
    ```

=== "MacOS"

    On ARM MacOS, download the build archive and extract it:

    ```console title="On local machine"
    wget https://package.cosmian.com/cli/5.16.1/macos_arm-release.zip
    unzip macos_arm-release.zip
    cp ./macos_arm-release/release/cosmian /usr/local/bin/
    chmod u+x /usr/local/bin/cosmian
    cosmian --version
    ```

    On Intel MacOS, download the build archive and extract it:

    ```console title="On local machine"
    wget https://package.cosmian.com/cli/5.16.1/macos_intel-release.zip
    unzip macos_intel-release.zip
    cp ./macos_intel-release/release/cosmian /usr/local/bin/
    chmod u+x /usr/local/bin/cosmian
    cosmian --version
    ```

=== "Windows"

    On Windows, download the build archive:

    ```console title="Build archive"
     https://package.cosmian.com/cli/5.16.1/windows-release.zip
    ```

    Extract the cosmian from:

    ```console title="cosmian for Windows"
    /windows-release/target/x86_64-pc-windows-msvc/release/cosmian.exe
    ```

    Copy it to a folder in your PATH and run it:

    ```console title="On local machine"
    cosmian --version
    ```
