## HSM keys

HSM keys are prefixed keys. They are created with a unique identifier that is pre-fixed by the `hsm` keyword and the
slot
number in the form:

```shell
hsm::<slot_number>::<key_identifier>
```

For instance, the key `hsm::1::mykey` is a key stored in the HSM slot 1 with the identifier `mykey`. Technically, this
identifier is stored in the `LABEL` field of the key object in the HSM.

Non-prefixed keys are considered KMS keys and are stored in the KMS database.

## KMIP operations

Some KMIP operations can be performed on HSM keys via the KMS server API.

First, make sure the HSM is configured and that the [Cosmian CLI](https://package.cosmian.com/cli/) is installed and
configured.

### Create

Create a new key in the HSM. The key unique must be provided on the request and must follow the
`hsm::<slot_number>::<key_identifier>` format described above.
Only the user identified by the `--hsm-admin` argument can create keys in the HSM.

RSA and AES keys are supported.
When creating an RSA key, the `key_identifier` will be that of the private key. The corresponding public key will be
automatically created and stored in the HSM with the same `key_identifier` but with the `_pk` suffix, for example, the
public key of the `hsm::1::mykey` private key will be created with unique identifier `has::1::mykey_pk`.

Create an RSA 4096-bit key with the Cosmiian CLI:

```shell
❯ cosmian kms rsa keys create --size_in_bits 4096 --sensitive hsm::4::my_rsa_key
The RSA key pair has been created.
      Public key unique identifier: hsm::4::my_rsa_key_pk
      Private key unique identifier: hsm::4::my_rsa_key
```

Create an AES 256-bit key with the Cosmiian CLI:

```shell
❯ cosmian kms sym keys create --algorithm aes --number-of-bits 256 --sensitive hsm::4::my_aes_key
The symmetric key was successfully generated.
	  Unique identifier: hsm::4::my_aes_key
```

Keys should be flagged as `sensitive` when created in the HSM, so that the private key or symmetric key cannot be
exported (see below `Get` and `Export`).

Note: HSM keys do not support object tagging in this release.

### Destroy

Contrarily to the KMS keys, HSM keys must not be Revoked before being Destroyed. The `Destroy` operation will remove the
key from the HSM.

Only the user identified by the `--hsm-admin` argument or a user which has been granted the `Destroy` operation (by the
HSM admin) can destroy keys in the HSM.

To destroy the key `hsm::4::my_rsa_key`, the following command can be used:

```shell
❯ cosmian kms rsa keys destroy --key-id hsm::4::my_rsa_key
Successfully destroyed the key.
      Unique identifier: hsm::4::mykey
```

To destroy the corresponding public key `hsm::4::my_rsa_key_pk`, the following command can be used:

```shell
❯ cosmian kms rsa keys destroy --key-id hsm::4::my_rsa_key_pk
Successfully destroyed the object.
	  Unique identifier: hsm::4::my_rsa_key_pk
```

### Get & Export

The `Get` and `Export` operations are used to retrieve the key material from the HSM.
Only the user identified by the `--hsm-admin` argument or a user which has been granted the `Get` operation (by the HSM
admin) can retrieve keys from the HSM.

Private keys or symmetric keys marked as `sensitive` cannot be retrieved from the HSM. The public key of a keypair can
always be retrieved.

To export the public key `hsm::4::my_rsa_key_pk` in PKCS#8 PEM format, the following command can be used:

```shell
❯ cosmian kms rsa keys export --key-id hsm::4::my_rsa_key_pk --key-format pkcs8-pem /tmp/pubkey.pem
The key hsm::4::my_rsa_key_pk of type PublicKey was exported to "/tmp/pubkey.pem"
	  Unique identifier: hsm::4::my_rsa_key_pk
```

To export the private key `hsm::4::mykey` in PKCS#8 PEM format, the following command can be used:

```shell
❯ cosmian kms rsa keys export --key-id hsm::4::my_rsa_key --key-format pkcs8-pem /tmp/privkey.pem
The key hsm::4::my_rsa_key of type PrivateKey was exported to "/tmp/privkey.pem"
	  Unique identifier: hsm::4::my_rsa_key
```

To export the symmetric key `hsm::4::my_aes_key` in raw format (i.e. raw bytes), 
the following command can be used:

```shell
❯ cosmian kms sym keys export --key-id hsm::4::my_aes_key --key-format raw /tmp/symkey.raw
The key hsm::4::my_aes_key of type SymmetricKey was exported to "/tmp/symkey.raw"
	  Unique identifier: hsm::4::my_aes_key
```

### Encrypt

Symmetric keys and public keys can be used to encrypt data. Only the user identified by the `--hsm-admin` argument or a
user which has been granted the `Encrypt` operation (by the HSM admin) can encrypt data with keys stored in the HSM.

For symmetric keys, only AES GCM is supported. For RSA keys, CKM_RSA_PKCS_OAEP and the now deprecated, but still widely
used, CKM_RSA_PKCS (v1.5) are supported. The hashing algorithm is fixed to SHA256.

When using RSA the maximum message size in bytes is:

 - PKCS#1 v1.5: (key size in bits / 8) - 11
 - OAEP: (key size in bits / 8) - 66

To encrypt a message with the public key `hsm::4::my_rsa_key_pk` and the CKM RSA PKCS OAEP algorithm, 
the following command can be used:

```shell
❯ cosmian kms rsa encrypt --key-id hsm::4::my_rsa_key_pk --encryption-algorithm ckm-rsa-pkcs-oaep \
/tmp/secret.txt
The encrypted file is available at "/tmp/secret.enc"
```

To encrypt a message using AES GCM with the symmetric key `hsm::4::my_aes_key`, the following command can be used:

```shell
❯ cosmian kms sym encrypt --key-id hsm::4::my_aes_key /tmp/secret.txt

### Decrypt

Symmetric keys and private keys can be used to decrypt data. Only the user identified by the `--hsm-admin` argument or a
user which has been granted the `Decrypt` operation (by the HSM admin) can decrypt data with keys stored in the HSM.

For symmetric keys, only AES GCM is supported. For RSA keys, CKM_RSA_PKCS_OAEP and the now deprecated, but still widely
used, CKM_RSA_PKCS (v1.5) are supported. The hashing algorithm is fixed to SHA256.

To decrypt a message with the private
key `hsm::4::mykey` and the CKM RSA PKCS OAEP algorithm, the following command can be used:

```shell
❯ cosmian kms rsa decrypt --key-id hsm::4::mykey --encryption-algorithm ckm-rsa-pkcs-oaep \
/tmp/secret.enc
The decrypted file is available at "/tmp/secret.plain"
```

## Creating a KMS key wrapped by an HSM key

To create a KMS key wrapped by an HSM key, the `--wrapping-key-id` argument must be used to specify the unique
identifier of the HSM key.

The user creating the key must be the HSM admin (see above) or have been granted the `Encrypt` operation on the HSM key.

For instance, the following command creates a 256-bit AES key wrapped by the HSM RSA (public) key `hsm::4::mykey_pk`:

```shell
❯ cosmian kms sym keys create --algorithm aes --number-of-bits 256 --sensitive \
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
❯ cosmian kms sym encrypt --key-id my_sym_key /tmp/secret.txt
The encrypted file is available at "/tmp/secret.enc"
```
