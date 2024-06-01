# A PKCS#11 provider for Cosmian KMS

This project builds libraries for Linux, MACOS and Windows, to use the Cosmian KMS as a PKCS#11
provider.

The PKCS#11 standard defines an API for cryptographic devices, such as hardware security modules (
HSMs) and smart cards.
The Cosmian KMS is a cloud-based cryptographic service that provides a secure and scalable key
management solution.

The PKCS#11 2.40 standard is available at
<https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html>

The primary goal is to support the Cosmian KMS as

- a Veracrypt keyfiles provider,
- a LUKS keys provider,

but it can be used with any application that supports PKCS#11.

## Prim'x

Generating a private key and certificate:

```shell
ckms.exe certificates certify -t disk-encryption -c primx --generate-key-pair --algorithm rsa2048 --subject-name "CN=Disk Encryption,OU=Org Unit,O=Org Name,L=City,ST=State,C=US" --certificate-extensions F:\primx.extensions` (exit code: 1)
PS F:\projects\kms> cargo run --bin ckms -- certificates certify -t disk-encryption -c primx  --generate-key-pair --algorithm rsa2048 --subject-name "CN=Disk Encryption,OU=Org Unit,O=Org Name,L=City,ST=State,C=US" --certificate-extensions F:\primx.extensions
```