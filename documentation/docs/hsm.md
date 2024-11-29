# HSM Support

Cosmian KMS natively integrates with
the [Proteccio](https://eviden.com/solutions/digital-security/data-encryption/trustway-proteccio-nethsm/) HSM.

## Main use case and benefit

The main use case for HSM support is to host keys in the KMS that are wrapped by keys stored in the HSM. This
combination provides the best of both worlds: the scalability and performance of the KMS at runtime, and the security of
the HSM at rest.

At rest, KMS keys are stored in the KMS database in a wrapped form, and the wrapping key is stored in the HSM. This
provides an additional layer of security for the keys stored in the KMS since the keys stored in the HSM are protected
by the HSM's hardware security mechanisms, and benefit from the HSM certifications.

At runtime, however, encryption and decryption requests from applications are processed by the KMS, which first unwraps
the keys stored in the KMS database using the keys stored in the HSM. Contrarily to the HSM, the KMS is a highly
scalable and performant system that can handle a large number of requests concurrently.

## Setup

This solution works on Linux (x64_86) and has been validated against the Proteccio `nethsm` library version 3.17.

The KMS expects the Proteccio `nethsm` library to be installed in `/lib/libnethsm.so` and the Proteccio configuration
files in `/etc/proteccio`. Please run the `nethsmstatus` tool to check the status of the HSM before proceeding with the
rest of the installation.

The KMS command line arguments to enable HSM support are:

```shell
--hsm-model "proteccio" \
--hsm-admin "<HSM_ADMIN_USERNAME>"  \
--hsm-slot <number_of_slot1> --hsm-password <password_of_slot1> \
--hsm-slot <number_of_slot2> --hsm-password <password_of_slot2>
...
```

The `--hsm-model` argument is the HSM model to be used; only `proteccio` is supported in this release.

The `--hsm-admin` argument is the username of the HSM administrator. The HSM administrator is the only user that can
create objects on the HSM via the KMIP `Create` operation the delegate other operations to other users. (see below)

The `--hsm-slot` and `--hsm-password` arguments are the slot number and password of the HSM slots to be used by the KMS.
These arguments can be repeated multiple times to specify multiple slots.

If using the TOML configuration file, see this [page](./index.md#toml-configuration-file) for more information on how to
configure the HSM support.

## HSM operations

HSM keys are created with a unique identifier that is pre-fixed by the `hsm` keyword and the slot number in the form:

```shell
hsm::<slot_number>::<key_identifier>
```

For instance, the key `hsm::1::mykey` is a key stored in the HSM slot 1 with the identifier `mykey`. Technically, this
identifier is stored in the `LABEL` field of the key object in the HSM.

The following KMIP operations can be performed on HSM keys via the KMS server API:

### `Create`

Create a new key in the HSM. The key unique must be provided on the request and must follow the
`hsm::<slot_number>::<key_identifier>` format described above.
Only the user identified by the `--hsm-admin` argument can create keys in the HSM.

RSA and AES keys are supported.
When creating an RSA key, the `key_identifier` will be that of the private key. The corresponding public key will be
automatically created and stored in the HSM with the same `key_identifier` but with the `_pk` suffix, for example, the
public key of the `hsm::1::mykey` private key will be created with unique identifier `has::1::mykey_pk`.

Using the `ckms` client, an RSA 4096-bit key can be created with the following command:

```shell
❯ ckms rsa keys create --size_in_bits 4096 --sensitive hsm::4::mykey
The RSA key pair has been created.
      Public key unique identifier: hsm::4::mykey_pk
      Private key unique identifier: hsm::4::mykey
```

Keys should be flagged as `sensitive` when created in the HSM, so that the private key or symmetric key cannot be
exported (see below `Get` and `Export`).

Note: HSM keys do not support object tagging in this release.

### `Destroy`

Contrarily to the KMS keys, HSM keys must not be Revoked before being Destroyed. The `Destroy` operation will remove the
key from the HSM.

Only the user identified by the `--hsm-admin` argument or a user which has been granted the `Destroy` operation (by the
HSM admin) can destroy keys in the HSM.

To destroy the key `hsm::4::mykey`, the following command can be used:

```shell
❯ ckms rsa keys destroy --key-id hsm::4::mykey
Successfully destroyed the key.
      Unique identifier: hsm::4::mykey
```

### `Get` & `Export`

The `Get` and `Export` operations are used to retrieve the key material from the HSM.
Only the user identified by the `--hsm-admin` argument or a user which has been granted the `Get` operation (by the HSM
admin) can retrieve keys from the HSM.

Private keys or symmetric keys marked as `sensitive` cannot be retrieved from the HSM. The public key of a keypair can
always be retrieved.

To export the public key `hsm::4::mykey_pk` in PKCS#8 PEM format, the following command can be used:

```shell
❯ ckms rsa keys export --key-id hsm::4::mykey_pk --key-format pkcs8-pem /tmp/pubkey.pem
The key hsm::4::mykey_pk of type PublicKey was exported to "/tmp/pubkey.pem"
      Unique identifier: hsm::4::mykey_pk
```

### `Encrypt`

Symmetric keys and public keys can be used to encrypt data. Only the user identified by the `--hsm-admin` argument or a
user which has been granted the `Encrypt` operation (by the HSM admin) can encrypt data with keys stored in the HSM.

For symmetric keys, only AES GCM is supported. For RSA keys, CKM_RSA_PKCS_OAEP and the now deprecated, but still widely
used, CKM_RSA_PKCS (v1.5) are supported. The hashing algorithm is fixed to SHA256.

To encrypt a message with the public key `hsm::4::mykey_pk` and the CKM RSA PKCS OAEP algorithm, the following command
can be used:

```shell
❯ ckms rsa encrypt --key-id hsm::4::mykey_pk --encryption-algorithm ckm-rsa-pkcs-oaep \
/tmp/secret.pem
The encrypted file is available at "/tmp/secret.enc"
```

### `Decrypt`

Symmetric keys and private keys can be used to decrypt data. Only the user identified by the `--hsm-admin` argument or a
user which has been granted the `Decrypt` operation (by the HSM admin) can decrypt data with keys stored in the HSM.

For symmetric keys, only AES GCM is supported. For RSA keys, CKM_RSA_PKCS_OAEP and the now deprecated, but still widely
used, CKM_RSA_PKCS (v1.5) are supported. The hashing algorithm is fixed to SHA256.

To decrypt a message with the private
key `hsm::4::mykey` and the CKM RSA PKCS OAEP algorithm, the following command can be used:

```shell
❯ ckms rsa decrypt --key-id hsm::4::mykey --encryption-algorithm ckm-rsa-pkcs-oaep \
/tmp/secret.enc
The decrypted file is available at "/tmp/secret.plain"
```

## Creating a KMS key wrapped by an HSM key

To create a KMS key wrapped by an HSM key, the `--wrapping-key-id` argument must be used to specify the unique
identifier of the HSM key.

The user creating the key must be the HSM admin (see above) or have been granted the `Encrypt` operation on the HSM key.

For instance, the following command creates a 256-bit AES key wrapped by the HSM RSA (public) key `hsm::4::mykey_pk`:

```shell
❯ ckms sym keys create --algorithm aes --number-of-bits 256 --sensitive \
--wrapping-key-id hsm::4::mykey_pk my_sym_key
The symmetric key was successfully generated.
      Unique identifier: my_sym_key
```

The symmetric key is now stored in the database encrypted (wrapped) by the HSM key. The encryption happened in the HSM.

The key can now be used to encrypt, and decrypt data, and the KMS will transparently unwrap the key using the HSM key.
This unwrapping will happen once, and the unwrapped symmetric key will be cached in memory for later operations; no
clear text symmetric key will be stored in the KMS database.

For example, to encrypt a message with the key `my_sym_key`, the following command can be used:

```shell
❯ ckms sym encrypt --key-id my_sym_key /tmp/secret.txt
The encrypted file is available at "/tmp/secret.enc"
```
