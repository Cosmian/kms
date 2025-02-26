=== "Ubuntu 22.04"

    Download package and install it:

    ```console title="On local machine"
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/cli/0.2.0/ubuntu-22.04/cosmian-cli_0.2.0-1_amd64.deb
    sudo apt install ./cosmian-cli_0.2.0-1_amd64.deb
    cosmian --version
    ```

=== "Ubuntu 24.04"

    Download package and install it:

    ```console title="On local machine"
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/cli/0.2.0/ubuntu-24.04/cosmian-cli_0.2.0-1_amd64.deb
    sudo apt install ./cosmian-cli_0.2.0-1_amd64.deb
    cosmian --version
    ```

=== "RHEL 9"

    Download package and install it:

    ```console title="On local machine"
    sudo dnf update && dnf install -y wget
    wget https://package.cosmian.com/cli/0.2.0/rhel9/cosmian_cli-0.2.0-1.x86_64.rpm
    sudo dnf install ./cosmian_cli-0.2.0-1.x86_64.rpm
    cosmian --version
    ```

=== "MacOS"

    On ARM MacOS, download the build archive and extract it:

    ```console title="On local machine"
    wget https://package.cosmian.com/cli/0.2.0/macos_arm-release.zip
    unzip macos_arm-release.zip
    cp ./macos_arm-release/release/cosmian /usr/local/bin/
    chmod u+x /usr/local/bin/cosmian
    cosmian --version
    cp ./macos_arm-release/release/cosmian_gui /usr/local/bin/
    chmod u+x /usr/local/bin/cosmian_gui
    ```

    On Intel MacOS, download the build archive and extract it:

    ```console title="On local machine"
    wget https://package.cosmian.com/cli/0.2.0/macos_intel-release.zip
    unzip macos_intel-release.zip
    cp ./macos_intel-release/release/cosmian /usr/local/bin/
    chmod u+x /usr/local/bin/cosmian
    cosmian --version
    cp ./macos_intel-release/release/cosmian_gui /usr/local/bin/
    chmod u+x /usr/local/bin/cosmian_gui
    ```

=== "Windows"

    On Windows, download the build archive:

    ```console title="Build archive"
     https://package.cosmian.com/cli/0.2.0/windows-release.zip
    ```

    Extract the cosmian from:

    ```console title="cosmian for Windows"
    /windows-release/target/x86_64-pc-windows-msvc/release/cosmian.exe
    ```

    Copy it to a folder in your PATH and run it:

    ```console title="On local machine"
    cosmian --version
    ```
