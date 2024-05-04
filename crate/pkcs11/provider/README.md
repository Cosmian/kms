# A PKCS#11 provider for Cosmian KMS

This project builds libraries for Linux, MACOS and Windows, to use the Cosmian KMS as a PKCS#11 provider.

The PKCS#11 standard defines an API for cryptographic devices, such as hardware security modules (HSMs) and smart cards.
The Cosmian KMS is a cloud-based cryptographic service that provides a secure and scalable key management solution.

The PKCS#11 2.40 standard is available at
<https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html>

The primary goal is to support the Cosmian KMS as

- a Veracrypt keyfiles provider,
- a LUKS keys provider,

but it can be used with any application that supports PKCS#11.
