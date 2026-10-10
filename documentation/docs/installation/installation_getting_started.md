# Getting started

Eviden KMS can be installed on various platforms, including Docker, Ubuntu, Rocky Linux, macOS, and Windows.
It is prepackaged with an integrated web ui (except for macOS) that is available on the `/ui` path of the server.

The KMS is also available on the marketplaces of major cloud providers, prepackaged to run confidentially in an Eviden VM.
Please check [this page](./marketplace_guide.md) for more information.

When installed using the options below, the KMS server will be automatically configured to run
using an SQLite database.
If you wish to change the database configuration, please refer to the [database guide](../configuration/database/configuration.md).

For high availability and scalability, refer to the [High Availability Guide](./high_availability_mode.md).

## Verifying release signatures

All Eviden KMS release packages (DEB, RPM, APK, DMG) are GPG-signed.
Each package is accompanied by a `.asc` signature file that can be used to verify its authenticity and integrity.
For Alpine `.apk` packages this is the only authenticity check: they are not signed with an `abuild` key,
so `apk` must be run with `--allow-untrusted` and cannot verify them itself.

### Import the Eviden public key**

```sh
gpg --import cosmian-kms-public.asc
```

The key is also bundled inside DMG installers and available in the [GitHub repository](https://github.com/Cosmian/kms/blob/develop/nix/signing-keys/cosmian-kms-public.asc).

### Verify a downloaded package**

```sh
gpg --verify <package>.asc <package>
```

For example:

```sh
# Debian package
gpg --verify cosmian-kms-server-non-fips-static-openssl_5.28.0_amd64.deb.asc \
             cosmian-kms-server-non-fips-static-openssl_5.28.0_amd64.deb

# RPM package
gpg --verify cosmian-kms-server-non-fips-static-openssl_5.28.0_x86_64.rpm.asc \
             cosmian-kms-server-non-fips-static-openssl_5.28.0_x86_64.rpm

# APK package (Alpine Linux)
gpg --verify cosmian-kms-server-non-fips_5.28.0-r0_x86_64.apk.asc \
             cosmian-kms-server-non-fips_5.28.0-r0_x86_64.apk

# DMG package
gpg --verify cosmian-kms-server-non-fips-static-openssl-5.28.0_arm64.dmg.asc \
             cosmian-kms-server-non-fips-static-openssl-5.28.0_arm64.dmg
```

A successful verification prints:

```text
gpg: Good signature from "Eviden KMS Release <tech@cosmian.com>"
```

!!!warning
    If the signature does not match, do not use the package.

## Installation

!!!info "KMS CLI"
    The KMS CLI lets you interact with the KMS from the command line. Install and configure it from [KMS CLI](../kms_clients/index.md).

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

=== "Debian-based distributions"

    Download the package and install it (works on all Debian distributions from Debian 10):

    ```sh
    sudo apt update && sudo apt install -y wget
    # Standard build (non-FIPS, static OpenSSL)
    wget https://package.cosmian.com/kms/5.28.0/deb/amd64/non-fips/static/cosmian-kms-server-non-fips-static-openssl_5.28.0_amd64.deb
    sudo apt install ./cosmian-kms-server-non-fips-static-openssl_5.28.0_amd64.deb
    sudo cosmian_kms --version
    ```

    Or install the FIPS build:

    ```sh
    wget https://package.cosmian.com/kms/5.28.0/deb/amd64/fips/static/cosmian-kms-server-fips-static-openssl_5.28.0_amd64.deb
    sudo apt install ./cosmian-kms-server-fips-static-openssl_5.28.0_amd64.deb
    sudo cosmian_kms --version
    ```

    A `cosmian_kms` service will be configured; the service file is located at `/etc/systemd/system/cosmian_kms.service`.
    To start the KMS, run:

    ```sh
    sudo systemctl start cosmian_kms
    ```

    - The server uses the configuration file located at `/etc/cosmian/kms.toml`.
    - The KMS UI is available at `http://localhost:9998/ui`.

=== "Rocky Linux distributions"

    Download the package and install it (works for Rocky Linux 8/9/10):

    ```sh
    sudo dnf update && sudo dnf install -y wget
    wget https://package.cosmian.com/kms/5.28.0/rpm/amd64/non-fips/static/cosmian-kms-server-non-fips-static-openssl_5.28.0_x86_64.rpm
    sudo dnf install ./cosmian-kms-server-non-fips-static-openssl_5.28.0_x86_64.rpm
    sudo cosmian_kms --version
    ```

    To start the KMS, run:

    ```sh
    sudo systemctl start cosmian_kms
    ```

    - The server uses the configuration file located at `/etc/cosmian/kms.toml`.
    - The KMS UI is available at `http://localhost:9998/ui`.

=== "Alpine Linux"

    Eviden KMS publishes an Alpine **`.apk`** server package (musl build) that runs
    natively on Alpine — no `gcompat` shim required. The package is GPG-signed
    out-of-band (`.apk.asc`) rather than with an `abuild` key, so `apk` cannot verify it
    itself and `--allow-untrusted` is required. **Verify the detached signature with `gpg`
    first (the snippets below do, and only install if the verification succeeds); it is the
    only authenticity check.** Obtain `cosmian-kms-public.asc` from a source independent of
    the package download (see [Verifying release signatures](#verifying-release-signatures)).
    The `ckms` CLI is packaged and
    documented separately — see [KMS CLI](../kms_clients/index.md) for the Alpine CLI
    package.

    ```sh
    apk add --no-cache gnupg wget
    gpg --import cosmian-kms-public.asc
    wget https://package.cosmian.com/kms/5.28.0/apk/amd64/fips/cosmian-kms-server-fips_5.28.0-r0_x86_64.apk
    wget https://package.cosmian.com/kms/5.28.0/apk/amd64/fips/cosmian-kms-server-fips_5.28.0-r0_x86_64.apk.asc
    gpg --verify cosmian-kms-server-fips_5.28.0-r0_x86_64.apk.asc cosmian-kms-server-fips_5.28.0-r0_x86_64.apk \
      && apk add --allow-untrusted ./cosmian-kms-server-fips_5.28.0-r0_x86_64.apk
    rc-update add cosmian_kms default
    rc-service cosmian_kms start
    ```

    The server package installs `/usr/sbin/cosmian_kms`, the configuration file
    `/etc/cosmian/kms.toml`, the web UI, and an OpenRC service (`/etc/init.d/cosmian_kms`,
    options in `/etc/conf.d/cosmian_kms`).

    The OpenRC service runs as a dedicated, unprivileged `kms` system user (not root), created automatically on install.
    `/etc/cosmian/kms.toml` is owned by `root:kms`, mode `0640` (readable by the service, writable only by root).
    `/var/lib/cosmian` and `/var/log/cosmian` are owned by `kms:kms`.
    If you bind-mount a custom config file or data directory, ensure it is readable/writable by the `kms` user (or its group).

    - **FIPS** (dynamically-linked musl): the package depends on `libgcc`, which `apk`
      installs automatically.
    - **non-FIPS** (fully static musl): no dependencies. Use the `non-fips` path and
      package name (`cosmian-kms-server-non-fips_…`).

    In a Dockerfile, copy the public key from your build context (obtained independently of
    the package download, e.g. from a pinned, reviewed copy of the
    [GitHub repository](https://github.com/Cosmian/kms/blob/develop/nix/signing-keys/cosmian-kms-public.asc)),
    download the package and its signature, and install only if `gpg --verify` succeeds:

    ```dockerfile
    FROM alpine:3.21
    COPY cosmian-kms-public.asc /tmp/cosmian-kms-public.asc
    ADD https://package.cosmian.com/kms/5.28.0/apk/amd64/fips/cosmian-kms-server-fips_5.28.0-r0_x86_64.apk /tmp/kms.apk
    ADD https://package.cosmian.com/kms/5.28.0/apk/amd64/fips/cosmian-kms-server-fips_5.28.0-r0_x86_64.apk.asc /tmp/kms.apk.asc
    RUN apk add --no-cache ca-certificates gnupg \
        && gpg --batch --import /tmp/cosmian-kms-public.asc \
        && gpg --batch --verify /tmp/kms.apk.asc /tmp/kms.apk \
        && apk add --no-cache --allow-untrusted /tmp/kms.apk \
        && apk del gnupg \
        && rm -rf /tmp/kms.apk /tmp/kms.apk.asc /tmp/cosmian-kms-public.asc /root/.gnupg
    ENV OPENSSL_CONF=/usr/local/cosmian/lib/ssl/openssl.cnf
    ENV OPENSSL_MODULES=/usr/local/cosmian/lib/ossl-modules
    EXPOSE 9998
    ENTRYPOINT ["/usr/sbin/cosmian_kms"]
    ```

    - The KMS UI is available at `http://localhost:9998/ui`.
    - **Known limitations** on the Alpine packages (see the
      [Alpine support note](../../../README.md#alpine-linux-musl) for details):
        - HSM backends (Utimaco, Proteccio, SmartCard HSM, Crypt2Pay) are not supported —
          vendor PKCS#11 drivers are glibc-only.
        - non-FIPS: old PKCS#12/RC2 import is unsupported (musl's static libc cannot
          `dlopen` the legacy OpenSSL provider). All other algorithms, including PQC and
          Covercrypt, are unaffected — the server logs a warning and continues.

=== "macOS"

    Download the installer for your architecture and run it:

    - Apple Silicon (ARM64):

        ```sh
        open "https://package.cosmian.com/kms/5.28.0/dmg/arm64/non-fips/static/cosmian-kms-server-non-fips-static-openssl-5.28.0_arm64.dmg"
        ```

    Then drag-and-drop the app to Applications or follow the DMG instructions.

    Note: The 5.28.0 DMG is provided for Apple Silicon (ARM64).

    After installation, run:

    ```sh
    /Applications/Cosmian\ KMS\ Server.app/Contents/MacOS/cosmian_kms --version
    /Applications/Cosmian\ KMS\ Server.app/Contents/MacOS/cosmian_kms
    ```

    - The server uses the configuration file located at `/etc/cosmian/kms.toml`.
    - The KMS UI is available at `http://localhost:9998/ui`.

### Static vs Dynamic builds

- Static builds: ship with OpenSSL statically linked into the binary. Simplest to deploy; no external crypto libraries required; consistent behavior across environments.
- Dynamic builds: link OpenSSL dynamically. This allows replacing the OpenSSL shared library at runtime to use custom or system-provided crypto. On Linux, replace the relevant `.so` files; on macOS, replace the `.dylib` files, ensuring ABI compatibility.

Available dynamic packages for Debian-based distributions:

```sh
# Non-FIPS dynamic (OpenSSL linked dynamically)
wget https://package.cosmian.com/kms/5.28.0/deb/amd64/non-fips/dynamic/cosmian-kms-server-non-fips-dynamic-openssl_5.28.0_amd64.deb
# FIPS dynamic
wget https://package.cosmian.com/kms/5.28.0/deb/amd64/fips/dynamic/cosmian-kms-server-fips-dynamic-openssl_5.28.0_amd64.deb
```

Available dynamic packages for Rocky Linux:

```sh
# Non-FIPS dynamic
wget https://package.cosmian.com/kms/5.28.0/rpm/amd64/non-fips/dynamic/cosmian-kms-server-non-fips-dynamic-openssl_5.28.0_x86_64.rpm
# FIPS dynamic
wget https://package.cosmian.com/kms/5.28.0/rpm/amd64/fips/dynamic/cosmian-kms-server-fips-dynamic-openssl_5.28.0_x86_64.rpm
```

To use custom OpenSSL with dynamic builds, install or place the desired OpenSSL
shared libraries here: `/usr/local/cosmian/lib/ossl-modules`.

=== "Windows"

    On Windows, download the NSIS installer:

    ```sh
    https://package.cosmian.com/kms/5.28.0/windows/x86_64/non-fips/static-openssl/cosmian-kms-server-non-fips-static-openssl_5.28.0_x86_64.exe
    ```

    Run the installer to install Eviden KMS Server. The installer will:
    - Install the KMS server with integrated web UI
    - Set up the configuration file at `C:\Users\<username>\AppData\Local\Eviden KMS Server\kms.toml`

    After installation, you can run the server:

    ```sh
    cosmian_kms --version
    ```

    - The KMS UI is available at `http://localhost:9998/ui`
    - The server uses the configuration file located at `C:\Users\<username>\AppData\Local\Eviden KMS Server\kms.toml`
    - See the [server configuration](../configuration/server_configuration_file.md) for more information
