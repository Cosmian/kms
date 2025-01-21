# Getting started

The **Cosmian KMS** is a high-performance,
[**open-source**](https://github.com/Cosmian/kms),
[FIPS 140-3 compliant](./fips.md) server application
written in [**Rust**](https://www.rust-lang.org/) that presents some unique features, such as:

- the ability to confidentially run in a public cloud — or any zero-trust environment — using
  Cosmian VM. See our cloud-ready confidential KMS on the
[Azure, GCP, and AWS marketplaces](https://cosmian.com/marketplaces/) and our [deployment guide](./marketplace_guide.md)
- support of state-of-the-art authentication mechanisms (see [authentication](./authentication.md))
- out-of-the-box support of
  [Google Workspace Client Side Encryption (CSE)](./google_cse/index.md)
- out-of-the-box support
  of [Microsoft Double Key Encryption (DKE)](./ms_dke/index.md)
- support for the [Proteccio HSM](./hsm.md) with KMS keys wrapped by the HSM
- [Veracrypt](./pkcs11/veracrypt.md)
  and [LUKS](./pkcs11/luks.md) disk encryption support
- [FIPS 140-3](./fips.md) mode gated behind the feature `fips`
- a [JSON KMIP 2.1](./kmip_2_1/index.md) compliant interface
- a full-featured client [command line and graphical interface](../cosmian_cli/index.md)
- a [high-availability mode](./high_availability_mode.md) with simple horizontal scaling
- a support of Python, Javascript, Dart, Rust, C/C++, and Java clients (see the `cloudproof` libraries
  on [Cosmian Github](https://github.com/Cosmian))
- integrated with [OpenTelemetry](https://opentelemetry.io/)

The **Cosmian KMS** is both a Key Management System and a Public Key Infrastructure.
As a KMS, it is designed to manage the lifecycle of keys and provide scalable cryptographic
services such as on-the-fly key generation, encryption, and decryption operations.

The **Cosmian KMS** supports all the standard NIST cryptographic algorithms as well as advanced post-quantum
cryptography algorithms such as [Covercrypt](https://github.com/Cosmian/cover_crypt).
Please refer to the list of [supported algorithms](./algorithms.md).

As a **PKI** it can manage root and intermediate certificates, sign and verify certificates, use
their public keys to encrypt and decrypt data.
Certificates can be exported under various formats including _PKCS#12_ modern and legacy flavor,
to be used in various applications, such as in _S/MIME_ encrypted emails.

## Easy to deploy

The **Cosmian KMS** is packaged as:

- [Debian](https://package.cosmian.com/kms/4.21.2/ubuntu-22.04/) or [RPM](https://package.cosmian.com/kms/4.21.2/rhel9/) package
- Docker [image](https://github.com/Cosmian/kms/pkgs/container/kms) and [FIPS image](https://github.com/Cosmian/kms/pkgs/container/kms)
- Pre-built [binaries](https://package.cosmian.com/kms/4.21.2/) for multiple operating systems (Linux, Windows, MacOS)

## Client CLI

The **Cosmian KMS** has an easy-to-use client command line interface built for many operating systems.
The [Cosmian CLI](../cosmian_cli/index.md) can manage the server, and the keys and perform operations such as encryption or decryption.

The **[Cosmian CLI](../cosmian_cli/index.md)** is packaged as:

- [Debian](https://package.cosmian.com/kms/4.21.2/ubuntu-22.04/) or [RPM](https://package.cosmian.com/kms/4.21.2/rhel9/) package
- Pre-built [binaries](https://package.cosmian.com/cli/) for multiple operating systems (Linux, Windows, MacOS)

**Note:** `ckms` has been replaced by [Cosmian CLI](../cosmian_cli/index.md) to manage other Cosmian products.

!!! info "Quick start"

    To quick-start a Cosmian KMS server on `http://localhost:9998` that stores its data
    inside the container, simply run the following command:

    ```sh
    docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest
    ```

    Using [Cosmian CLI](../cosmian_cli/index.md), you can easily manage the server:

    1) Create a 256-bit symmetric key

    ```sh
    cosmian kms sym keys create --number-of-bits 256 --algorithm aes --tag my-file-key
    ...
    The symmetric key was successfully generated.
          Unique identifier: 87e9e2a8-4538-4701-aa8c-e3af94e44a9e
    ```

    2) Encrypt the `image.png` file with AES GCM using the key

    ```sh
    cosmian kms sym encrypt --tag my-file-key --output-file image.enc image.png
    ...
    The encrypted file is available at "image.enc"
    ```

    3) Decrypt the `image.enc` file using the key
    ```sh
    cosmian kms sym decrypt --tag my-file-key --output-file image2.png image.enc
    ...
    The decrypted file is available at "image2.png"
    ```
