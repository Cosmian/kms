=== "Debian/Ubuntu (amd64)"

    Download package and install it:

    ```console title="On local machine"
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/kms/5.16.2/deb/amd64/non-fips/static/cosmian-kms-cli-non-fips-static-openssl_5.16.2_amd64.deb
    sudo apt install ./cosmian-kms-cli-non-fips-static-openssl_5.16.2_amd64.deb
    ckms --version
    ```

=== "Debian/Ubuntu (arm64)"

    Download package and install it:

    ```console title="On local machine"
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/kms/5.16.2/deb/arm64/non-fips/static/cosmian-kms-cli-non-fips-static-openssl_5.16.2_arm64.deb
    sudo apt install ./cosmian-kms-cli-non-fips-static-openssl_5.16.2_arm64.deb
    ckms --version
    ```

=== "RHEL/Rocky Linux (x86_64)"

    Download package and install it:

    ```console title="On local machine"
    sudo dnf update && sudo dnf install -y wget
    wget https://package.cosmian.com/kms/5.16.2/rpm/amd64/non-fips/static/cosmian-kms-cli-non-fips-static-openssl_5.16.2_x86_64.rpm
    sudo dnf install ./cosmian-kms-cli-non-fips-static-openssl_5.16.2_x86_64.rpm
    ckms --version
    ```

=== "RHEL/Rocky Linux (aarch64)"

    Download package and install it:

    ```console title="On local machine"
    sudo dnf update && sudo dnf install -y wget
    wget https://package.cosmian.com/kms/5.16.2/rpm/arm64/non-fips/static/cosmian-kms-cli-non-fips-static-openssl_5.16.2_aarch64.rpm
    sudo dnf install ./cosmian-kms-cli-non-fips-static-openssl_5.16.2_aarch64.rpm
    ckms --version
    ```

=== "MacOS (Apple Silicon)"

    Download the DMG installer and install it:

    ```console title="On local machine"
    wget https://package.cosmian.com/kms/5.16.2/dmg/arm64/non-fips/static/cosmian-kms-cli-non-fips-static-openssl-5.16.2_arm64.dmg
    sudo hdiutil attach cosmian-kms-cli-non-fips-static-openssl-5.16.2_arm64.dmg
    sudo installer -pkg /Volumes/cosmian-kms-cli/cosmian-kms-cli.pkg -target /
    hdiutil detach /Volumes/cosmian-kms-cli
    ckms --version
    ```

=== "Windows"

    On Windows, download the installer:

    ```console title="Build archive"
     https://package.cosmian.com/kms/5.16.2/windows/x86_64/non-fips/static-openssl/cosmian-kms-cli-non-fips-static-openssl_5.16.2_x86_64.exe
    ```

    Run the installer and add the installation directory to your PATH, then run:

    ```console title="On local machine"
    ckms --version
    ```
