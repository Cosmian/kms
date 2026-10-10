# Installation

=== "Debian/Ubuntu (amd64)"

    Download package and install it:

    ```console title="On local machine"
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/kms/5.28.0/deb/amd64/non-fips/static/cosmian-kms-cli-non-fips-static-openssl_5.28.0_amd64.deb
    sudo apt install ./cosmian-kms-cli-non-fips-static-openssl_5.28.0_amd64.deb
    ckms --version
    ```

=== "Debian/Ubuntu (arm64)"

    Download package and install it:

    ```console title="On local machine"
    sudo apt update && sudo apt install -y wget
    wget https://package.cosmian.com/kms/5.28.0/deb/arm64/non-fips/static/cosmian-kms-cli-non-fips-static-openssl_5.28.0_arm64.deb
    sudo apt install ./cosmian-kms-cli-non-fips-static-openssl_5.28.0_arm64.deb
    ckms --version
    ```

=== "RHEL/Rocky Linux (x86_64)"

    Download package and install it:

    ```console title="On local machine"
    sudo dnf update && sudo dnf install -y wget
    wget https://package.cosmian.com/kms/5.28.0/rpm/amd64/non-fips/static/cosmian-kms-cli-non-fips-static-openssl_5.28.0_x86_64.rpm
    sudo dnf install ./cosmian-kms-cli-non-fips-static-openssl_5.28.0_x86_64.rpm
    ckms --version
    ```

=== "RHEL/Rocky Linux (aarch64)"

    Download package and install it:

    ```console title="On local machine"
    sudo dnf update && sudo dnf install -y wget
    wget https://package.cosmian.com/kms/5.28.0/rpm/arm64/non-fips/static/cosmian-kms-cli-non-fips-static-openssl_5.28.0_aarch64.rpm
    sudo dnf install ./cosmian-kms-cli-non-fips-static-openssl_5.28.0_aarch64.rpm
    ckms --version
    ```

=== "Alpine Linux (amd64)"

    Download the package and its detached GPG signature, verify it, then install it
    (musl build, no `gcompat` shim required). The `.apk` is signed out-of-band with the
    Eviden release key rather than with an `abuild` key, so `apk` cannot check it itself
    and `--allow-untrusted` is required: **the `gpg --verify` step is therefore the only
    authenticity check — do not skip it.** Obtain `cosmian-kms-public.asc` from a source
    independent of the package download (see
    [Verifying release signatures](../installation/installation_getting_started.md#verifying-release-signatures)).

    ```console title="On local machine"
    apk add --no-cache gnupg wget
    gpg --import cosmian-kms-public.asc
    wget https://package.cosmian.com/kms/5.28.0/apk/amd64/non-fips/cosmian-kms-cli-non-fips_5.28.0-r0_x86_64.apk
    wget https://package.cosmian.com/kms/5.28.0/apk/amd64/non-fips/cosmian-kms-cli-non-fips_5.28.0-r0_x86_64.apk.asc
    gpg --verify cosmian-kms-cli-non-fips_5.28.0-r0_x86_64.apk.asc cosmian-kms-cli-non-fips_5.28.0-r0_x86_64.apk \
      && apk add --allow-untrusted ./cosmian-kms-cli-non-fips_5.28.0-r0_x86_64.apk
    ckms --version
    ```

=== "Alpine Linux (arm64)"

    Download the package and its detached GPG signature, verify it, then install it
    (musl build, no `gcompat` shim required). The `.apk` is signed out-of-band with the
    Eviden release key rather than with an `abuild` key, so `apk` cannot check it itself
    and `--allow-untrusted` is required: **the `gpg --verify` step is therefore the only
    authenticity check — do not skip it.** Obtain `cosmian-kms-public.asc` from a source
    independent of the package download (see
    [Verifying release signatures](../installation/installation_getting_started.md#verifying-release-signatures)).

    ```console title="On local machine"
    apk add --no-cache gnupg wget
    gpg --import cosmian-kms-public.asc
    wget https://package.cosmian.com/kms/5.28.0/apk/arm64/non-fips/cosmian-kms-cli-non-fips_5.28.0-r0_aarch64.apk
    wget https://package.cosmian.com/kms/5.28.0/apk/arm64/non-fips/cosmian-kms-cli-non-fips_5.28.0-r0_aarch64.apk.asc
    gpg --verify cosmian-kms-cli-non-fips_5.28.0-r0_aarch64.apk.asc cosmian-kms-cli-non-fips_5.28.0-r0_aarch64.apk \
      && apk add --allow-untrusted ./cosmian-kms-cli-non-fips_5.28.0-r0_aarch64.apk
    ckms --version
    ```

=== "MacOS (Apple Silicon)"

    Download the DMG installer and install it:

    ```console title="On local machine"
    wget https://package.cosmian.com/kms/5.28.0/dmg/arm64/non-fips/static/cosmian-kms-cli-non-fips-static-openssl-5.28.0_arm64.dmg
    sudo hdiutil attach cosmian-kms-cli-non-fips-static-openssl-5.28.0_arm64.dmg
    sudo installer -pkg /Volumes/cosmian-kms-cli/cosmian-kms-cli.pkg -target /
    hdiutil detach /Volumes/cosmian-kms-cli
    ckms --version
    ```

=== "Windows"

    On Windows, download the installer:

    ```console title="Build archive"
     https://package.cosmian.com/kms/5.28.0/windows/x86_64/non-fips/static-openssl/cosmian-kms-cli-non-fips-static-openssl_5.28.0_x86_64.exe
    ```

    Run the installer and add the installation directory to your PATH, then run:

    ```console title="On local machine"
    ckms --version
    ```
