=== "Ubuntu 20.04"

    Download package and install it:

    ```console title="On local machine"
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/kms/4.19.3/ubuntu-20.04/cosmian-kms-cli_4.19.3-1_amd64.deb
    sudo apt install ./cosmian-kms-cli_4.19.3-1_amd64.deb
    ckms --version
    ```

    Or install the FIPS version:

    ```console title="FIPS version"
    wget https://package.cosmian.com/kms/4.19.3/ubuntu-20.04/cosmian-kms-cli-fips_4.19.3-1_amd64.deb
    sudo apt install ./cosmian-kms-cli-fips_4.19.3-1_amd64.deb
    ckms --version
    ```

=== "Ubuntu 22.04"

    Download package and install it:

    ```console title="On local machine"
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/kms/4.19.3/ubuntu-22.04/cosmian-kms-cli_4.19.3-1_amd64.deb
    sudo apt install ./cosmian-kms-cli_4.19.3-1_amd64.deb
    ckms --version
    ```

    Or install the FIPS version:

    ```console title="FIPS version"
    wget https://package.cosmian.com/kms/4.19.3/ubuntu-22.04/cosmian-kms-cli-fips_4.19.3-1_amd64.deb
    sudo apt install ./cosmian-kms-cli-fips_4.19.3-1_amd64.deb
    ckms --version
    ```

=== "Ubuntu 24.04"

    Download package and install it:

    ```console title="On local machine"
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/kms/4.19.3/ubuntu-24.04/cosmian-kms-cli_4.19.3-1_amd64.deb
    sudo apt install ./cosmian-kms-cli_4.19.3-1_amd64.deb
    ckms --version
    ```

    Or install the FIPS version:

    ```console title="FIPS version"
    wget https://package.cosmian.com/kms/4.19.3/ubuntu-24.04/cosmian-kms-cli-fips_4.19.3-1_amd64.deb
    sudo apt install ./cosmian-kms-cli-fips_4.19.3-1_amd64.deb
    ckms --version
    ```

=== "RHEL 9"

    Download package and install it:

    ```console title="On local machine"
    sudo dnf update && dnf install -y wget
    wget https://package.cosmian.com/kms/4.19.3/rhel9/cosmian_kms_cli-4.19.3-1.x86_64.rpm
    sudo dnf install ./cosmian_kms_cli-4.19.3-1.x86_64.rpm
    ckms --version
    ```

=== "MacOS"

    On ARM MacOS, download the build archive and extract it:

    ```console title="On local machine"
    wget https://package.cosmian.com/kms/4.19.3/macos_arm-release.zip
    unzip macos_arm-release.zip
    cp /macos_arm-release/Users/runner/work/kms/kms/target/aarch64-apple-darwin/release/ckms /usr/local/bin/
    chmod u+x /usr/local/bin/ckms
    ckms --version
    ```

    On Intel MacOS, download the build archive and extract it:

    ```console title="On local machine"
    wget https://package.cosmian.com/kms/4.19.3/macos_intel-release.zip
    unzip macos_intel-release.zip
    cp /macos_intel-release/Users/runner/work/kms/kms/target/x86_64-apple-darwin/release/ckms /usr/local/bin/
    chmod u+x /usr/local/bin/ckms
    ckms --version
    ```

=== "Windows"

    On Windows, download the build archive:

    ```console title="Build archive"
     https://package.cosmian.com/kms/4.19.3/windows-release.zip
    ```

    Extract the ckms from:

    ```console title="ckms for Windows"
    /windows-release/target/x86_64-pc-windows-msvc/release/ckms.exe
    ```

    Copy it to a folder in your PATH and run it:

    ```console title="On local machine"
    ckms --version
    ```
