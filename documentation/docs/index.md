The Cosmian KMS is a high-performance, [**open-source**](https://github.com/Cosmian/kms), server application
written in [**Rust**](https://www.rust-lang.org/) that provides a [**KMIP 2.1**](#kmip-21-api)
REST API.

The Cosmian KMS is both a Key Management System and a Public Key Infrastructure.
As a KMS, it is designed to manage the lifecycle of keys and provide scalable cryptographic
services such as on-the-fly key generation, encryption, and decryption operations.

The KMS supports all the standard NIST cryptographic algorithms as well as advanced post-quantum
cryptography algorithms such as [Covercrypt](https://github.com/Cosmian/cover_crypt).

As a PKI it can manage root and intermediate certificates, sign and verify certificates, use
their public keys to encrypt and decrypt data.
Certificates can be exported under various formats including PKCS#12 modern and legacy flavor,
to be used in various applications, such as in S/MIME encrypted emails.

!!! info "Quick start"

    To quick-start a Cosmian KMS server on `http://localhost:9998` that stores its data
    inside the container, simply run the following command:

    ```sh
    docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:4.20.0
    ```

    Pre-built binaries, for both the server and CLI (called `cosmian`) are available for multiple
    operating systems on [Cosmian packages](https://package.cosmian.com/cli/0.1.0/).

    Using [Cosmian CLI](/cosmian_cli), you can easily manage the server:

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

## Public Source Code

The server's source code is fully available on [GitHub](https://github.com/Cosmian/kms) under a
Business Source License so that it can be audited and improved by anyone.

## KMIP 2.1 API

The Cosmian KMS server exposes a **KMIP 2.1** REST API on the `/kmip_2_1` endpoint that follows
the [JSON profile](https://docs.oasis-open.org/kmip/kmip-profiles/v2.1/os/kmip-profiles-v2.1-os.html#_Toc32324415)
of
the
OASIS-normalized [KMIP 2.1 specifications](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/cs01/kmip-spec-v2.1-cs01.html).

Check the [KMIP 2.1](./kmip_2_1/index.md) page for details.

## Supports Google Workspace Client Side Encryption

The KMS server can be used as a Key Management System for the Google Workspace Client Side
Encryption feature.
Please check the [Google Workspace Client Side Encryption](./google_cse/google_cse.md) page for
details.

## Supports Microsoft Double Key Encryption

The KMS server can be used as a Key Management System for the Microsoft Double Key Encryption
feature.
Please check the [Microsoft Double Key Encryption](./ms_dke/ms_dke.md) page for details.

## FIPS 140-3 certifications

When run in FIPS mode, the Cosmian KMS uses only cryptographic primitives that are compliant with
the standards of the National Institute of Standards and Technology (NIST) and uses
implementations of an NIST FIPS 140–3 compliant cryptographic module.
See [FIPS mode](./fips.md)

## Support for Proteccio HSMs

The Cosmian KMS can be configured to use Proteccio HSMs to store and manage keys and create KMS keys wrapped by the HSM
keys. This provides the best of both worlds: the security of an HSM at rest and the scalability of a KMS at runtime.
Check the [HSM](./hsm.md) page for details.

## Veracrypt and LUKS disk encryption support

The KMS server can provide keys on the fly to mount LUKS and Veracrypt encrypted volumes using
its PKCS#11 module. With LUKS, the decryption key never leaves the KMS server.
Check the [Veracrypt](./pkcs11/veracrypt.md) and [LUKS](./pkcs11/luks.md) pages for details.

## State-of-the-art authentication

State-of-the-art authentication facilitates integration with existing IT infrastructure and allows
single sign-on
scenarios.

Server access is secured using native TLS combined with [Open ID-compliant](https://openid.net/) JWT access tokens or TLS client certificates.

Check the enabling [TLS documentation](./tls.md) as well as
the [authentication documentation](./authentication.md) for details.

## High-availability and databases

The Cosmian KMS may be deployed either in [single-server mode](./single_server_mode.md) or for [high availability](./high_availability_mode.md)
using simple horizontal scaling of the servers.

For additional security, the server supports concurrent user encrypted databases in single-server mode and an application-level encrypted database on top of Redis in a high-availability scenario.

## Designed to securely run in the Public Cloud or other Zero-Trust environments

When running on top of Cosmian VMs with a fully application-level encrypted
Redis database, the Cosmian KMS can securely run in zero-trust environments, such as the public cloud.

See our cloud-ready confidential KMS on the
[Azure, GCP, and AWS marketplaces](https://cosmian.com/marketplaces/) and our [deployment guide](./marketplace_guide.md)

## Support for object tagging

The KMS server supports user tagging of objects to facilitate their management.
Specify as many user tags as needed when creating and importing objects.

In addition, the KMS server will automatically add a system tag based on the object type:

- `_sk`: for a private key
- `_pk`: for a public key
- `_kk`: for a symmetric key
- `_uk`: for a Covercrypt user decryption key
- `_cert`: for a X509 certificate

Use the tags to export objects, locate them, or request data encryption and decryption.

## Command line interface client

The KMS has an easy-to-use command line interface client built for many operating systems.

The [Cosmian CLI](/cosmian_cli) can manage the server, and the keys and perform operations such as encryption or decryption.

Check the [Cosmian CLI](/cosmian_cli) for details.

## Easy to deploy: Docker images and pre-built binaries

The KMS server is available as a Docker image on
the [Cosmian public Docker repository](https://github.com/Cosmian/kms/pkgs/container/kms).

Raw binaries for multiple operating systems are also available on
the [Cosmian public packages repository](https://package.cosmian.com/kms/4.20.0/)

## Integrated with OpenTelemetry

The KMS server can be configured to send telemetry traces to
an [OpenTelemetry](https://opentelemetry.io/) collector.

## Integrated with Cloudproof libraries

To build the next generation of privacy-by-design applications with end-to-end encryption, the KMS server is integrated with the **Cloudproof**
libraries to deliver keys and secrets to the client-side cryptographic stacks or perform
delegated encryption and decryption.

The libraries are available in many languages, including JavaScript, Java, Dart, and Python. Check their [documentation](https://github.com/search?q=topic%3Acloudproof+org%3ACosmian+fork%3Atrue&type=repositories) for details.
