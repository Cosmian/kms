The **Cosmian KMS** is a high-performance,
[**open-source**](https://github.com/Cosmian/kms),
[FIPS 140-3 compliant](./fips.md) server application
written in [**Rust**](https://www.rust-lang.org/) that presents some unique features, such as:

- Delivering encryption and decryption services at a very high rate (up to **millions of operations per second**), close
  to the applications that use it, while keeping the keys in a secure environment backed by HSMs.
- Flexible per-CPU pricing with no hidden costs lets you deploy and scale any number of servers where you need them.
- the ability to confidentially run in a public cloud, or any zero-trust environment, using
  Cosmian VM. See our cloud-ready confidential KMS on the
  [Azure, GCP, and AWS marketplaces](https://cosmian.com/marketplaces/) and
  our [deployment guide](installation/marketplace_guide.md)
- support of state-of-the-art authentication mechanisms (see [authentication](./authentication.md))
- out-of-the-box support of
  [Google Workspace Client Side Encryption (CSE)](./google_cse/index.md)
  and  [Microsoft 365 Double Key Encryption (DKE)](./ms_dke/index.md)
- support for [HSMs](./hsms/index.md) (trustway Proteccio, Utimaco general purpose) with KMS keys wrapped by the HSM
- [Veracrypt](./pkcs11/veracrypt.md)
  and [LUKS](./pkcs11/luks.md) disk encryption support
- VMware, Oracle Database TDE (and more...) integration
- [FIPS 140-3](./fips.md) mode gated behind the feature `fips`
- KMIP 1.0, 1.1, 1.2, 1.3, 1.4. 2.0 and 2.1, in both binary and JSON format. See [KMIP](./kmip_2_1/index.md) for
  details.
- a full-featured client [command line and graphical interface](../cosmian_cli/index.md)
- a [high-availability mode](installation/high_availability_mode.md) with simple horizontal scaling
- a support of Python, JavaScript, Dart, Rust, C/C++, and Java clients (see the `cloudproof` libraries
  on [Cosmian Github](https://github.com/Cosmian))
- integrated with [OpenTelemetry](https://opentelemetry.io/)

The **Cosmian KMS** is a Key Management System, an Encryption Oracle, and a Public Key Infrastructure.

- As **a key management system**, it is designed to manage the lifecycle of keys and provide services such as on-the-fly
  key generation and revocation, including in [connected HSMs](./hsms/index.md).
- As an encryption oracle**, it provides high-availability, high-scalability, encryption, and decryption operations.
  This
  is the Cosmian KMS's strong point, offering **millions of operations in seconds** while providing high security for
  keys
  when [backed by an HSM](./hsms/index.md).
- As a **PKI**, it can manage root and intermediate certificates, sign and verify certificates, and use
  their public keys to encrypt and decrypt data.
  Certificates can be exported under various formats, including _PKCS#12_ modern and legacy flavor,
  to be used in various applications, such as in _S/MIME_ encrypted emails.

The **Cosmian KMS** supports all the standard NIST cryptographic algorithms as well as advanced post-quantum
cryptography algorithms such as [Covercrypt](https://github.com/Cosmian/cover_crypt).
Please refer to the list of [supported algorithms](./algorithms.md).

## Easy to deploy

The **Cosmian KMS** is packaged as:

- [Debian](https://package.cosmian.com/kms/4.24.0/ubuntu-22.04/)
  or [RPM](https://package.cosmian.com/kms/4.24.0/rockylinux9/)
  package
- Docker [image](https://github.com/Cosmian/kms/pkgs/container/kms)
  and [FIPS image](https://github.com/Cosmian/kms/pkgs/container/kms)
- Pre-built [binaries](https://package.cosmian.com/kms/4.24.0/) for multiple operating systems (Linux, Windows, MacOS)

## User Interface

The **Cosmian KMS** comes with an easy-to-use graphical user interface
(GUI) that supports authentication using client certificates and OIDC tokens.
![Cosmian KMS UI](./images/kms-ui.png)

## Client CLI

The **Cosmian KMS** has a client command line interface (CLI) with integrated help, built for many operating systems.
The [Cosmian CLI](../cosmian_cli/index.md) can manage the server and the keys, and perform operations such as encryption
or decryption.

The **[Cosmian CLI](../cosmian_cli/index.md)** is packaged as:

- [Debian](https://package.cosmian.com/kms/4.24.0/ubuntu-22.04/)
  or [RPM](https://package.cosmian.com/kms/4.24.0/rockylinux9/)
  package
- Pre-built [binaries](https://package.cosmian.com/cli/) for multiple operating systems (Linux, Windows, MacOS)

**Note:** `cosmian` has been replaced by [Cosmian CLI](../cosmian_cli/index.md) to manage other Cosmian products.
