The CLI enables you to interact with the KMS to manage keys and encrypt or decrypt data.

You first need to write a configuration file as follows:

```json
{
  "kms_server_url": "http://127.0.0.1:9998",
  "kms_access_token": "MY_TOKEN"
}
```

The `kms_server_url` is the remote URL of the KMS you want to query.
The `kms_access_token` is the access token that authenticates you to the KMS server. If the server runs without Auth0, you can let `kms_access_token` empty.

You can also add `"insecure': true` to allow the CLI to connect to a KMS using a self-signed SSL certificate. For instance, it could be the case when running tests with the on-premise version.

The CLI expects to find a file named `kms.json` in the current directory or a path set in the `KMS_CLI_CONF` environment variable.

```
$ KMS_CLI_CONF=kms.json cosmian_kms_cli --help
```

## ABE Covercrypt

\_In the following examples, we describe how to use the CLI using Covercrypt (`cc`).

### Generate the master key

Create a new ABE master access key pair for a given policy. The master public key encrypts files and can be safely shared. However, the master secret key generates user decryption keys and must be kept confidential. Both of them are stored inside the KMS. This command returns a couple of IDs referring to this new key pair.

```sh
$ cosmian_kms_cli cc init -p policy.json
The master key pair has been properly generated.
Store the following securely for any further uses:

  Private key unique identifier: 8dd701d8-b4e8-4eb0-a1eb-8bb72bc6a3ee

  Public key unique identifier: b5193e13-784c-4b24-a8cf-b58a34d90e0f
```

The file `policy.json` describes the policies. Find below an example:

```json
{
  "policy": {
    "level": {
      "hierarchical": true,
      "attributes": ["confidential", "secret", "top-secret"]
    },
    "department": {
      "hierarchical": false,
      "attributes": ["finance", "marketing", "operations"]
    }
  },
  "max-rotations": 100
}
```

### Generate a user decryption key

Generate a new user decryption key given an access policy expressed as a boolean
expression. The user decryption key can decrypt files with attributes matching its access policy (i.e. the access policy is true). This command returns the ID referring to this
new decryption key.

```sh
$ cosmian_kms_cli cc new -s  8dd701d8-b4e8-4eb0-a1eb-8bb72bc6a3ee "(department::marketing || department::finance) && level::secret"
The decryption user key has been properly generated.
Store the following securely for any further uses:

  Decryption user key unique identifier: bc103f01-000a-4da4-8ecd-848684e8b238
```

### Encrypt

It encrypts a file with the given policy attributes and the public key stored in the KMS.

```sh
$ cosmian_kms_cli cc encrypt --access-policy "department::marketing && level::confidential" -o /tmp -p b5193e13-784c-4b24-a8cf-b58a34d90e0f my_file
The encryption has been properly done.
The encrypted file can be found at /tmp/my_file.enc
```

### Decrypt

It decrypts a file identified by its name and gives a user decryption key stored in the KMS.

```sh
$ cosmian_kms_cli cc decrypt -u bc103f01-000a-4da4-8ecd-848684e8b238 -o /tmp /tmp/my_file.enc
The decryption has been properly done.
The decrypted file can be found at /tmp/my_file.plain
```

### Export

Export a key from the KMS in TTLV serialized format.

```sh
cosmian_kms_cli cc export -i b5193e13-784c-4b24-a8cf-b58a34d90e0f -o /tmp/key.json
```

### Import

Import a TTLV serialized key into the KMS.

```sh
cosmian_kms_cli cc import -i unique_uid -f /tmp/master_private_key.json -r
```

### Export-keys

Export from the KMS a key by its KMS ID. The key exported is in raw format.

```sh
$ cosmian_kms_cli cc export-keys -k b5193e13-784c-4b24-a8cf-b58a34d90e0f /tmp/key
The key has been properly exported.
The key file can be found at /tmp/key
```

If the key is stored wrapped inside the KMS, you can unwrap it after getting it and before storing it on the disk by adding `-W my_password`.

### Import-keys

Import (wrapped, to wrap, or unwrapped) keys for a given user. The import keys are in raw format.

For a master key pair, you can proceed as follow:

```sh
$ cosmian_kms_cli cc import-keys --secret-key-file /tmp/key.private  --public-key-file /tmp/key.public  --policy crate/cli/policy.json
The master key pair has been properly imported.
Store the following securely for any further uses:

  Private key unique identifier: 33892479-7ee1-4b22-ab24-9ac6b6ed7c25

  Public key unique identifier: f2216ee6-9166-487b-8191-3b6c227fd12d

```

For a user decryption key:

```sh
cosmian_kms_cli cc import-keys --user-key-file /tmp/key --secret-key-id 33892479-7ee1-4b22-ab24-9ac6b6ed7c25 -a "(department::marketing || department::finance) && level::secret"
The decryption user key has been properly imported.
Store the following securely for any further uses:

  Decryption user key unique identifier: 24a112dc-3239-4549-a6a7-8b7879c77d19
```

The two previous examples have imported plain-text keys. You also can import wrapped keys as follow:

- If the keys have been wrapped on your own, you just need to say it to the CLI using `-w`.
- If you rely on the CLI to wrap the key before sending it to the KMS server, you can add `-W my_password`.

### Rotate the keys

Rotate an attribute and update the master public key file. New files encrypted with the rotated attribute cannot be decrypted by user decryption keys until they have been re-keyed.

```sh
$ cosmian_kms_cli cc rotate -a department::marketing -a level::confidential -s 33892479-7ee1-4b22-ab24-9ac6b6ed7c25
The master key pair has been properly rotated.
```

### Revoke a user decryption key

Not implemented yet

### Destroy a user decryption key

Destroy the decryption key for a given user

```sh
$ cosmian_kms_cli cc destroy -u 24a112dc-3239-4549-a6a7-8b7879c77d19
The decryption user key has been properly destroyed.
```

# Permissions and objects

## List the objects you owned

```sh
$ cosmian_kms_cli permission owned
The objects are:

[Active] ac022289-284c-4264-9f02-998c62c38760 - AbeMasterSecretKey
[Active] 48ff0c5d-ef88-48eb-828c-51743e7056da - AbeMasterSecretKey
[Active] 35b3d81e-6ab8-48d0-9f80-5edf23460cd9 - AbeMasterSecretKey
[Active] 58793b0a-f943-4d6c-8db0-195e885fd9fb - AbeUserDecryptionKey
[Active][Wrapped] 04bf5ed1-716c-49fe-8f46-c67aca238fc3 - AbeMasterSecretKey
[Destroyed] 24a112dc-3239-4549-a6a7-8b7879c77d19 - CoverCryptSecretKey
...
```

## List the objects shared with you

```sh
$ cosmian_kms_cli permission shared
The objects are:

[Active] ac02aaaa-284c-4264-9f02-998c62c38760 - AbeMasterSecretKey
```

## Share an object with another user

In that example, we only share a key for the user `test@example.com` for the `encrypt` operation.

```sh
$ cosmian_kms_cli permission add --user test@google.com --operation encrypt b7c0e623-7800-4f87-a347-63bcf22cbd04
The permission has been properly set
```

You can call this command several times on every operation you want to allow. See [authorization](authorization.md).

## Remove a share

```sh
$ cosmian_kms_cli permission remove --user test@google.com --operation encrypt b7c0e623-7800-4f87-a347-63bcf22cbd04
The permission has been properly removed
```

You can call this command several times on every operation you want. See [authorization](authorization.md).

## List permissions on an object

```sh
$ cosmian_kms_cli permission list  b7c0e623-7800-4f87-a347-63bcf22cbd04
The permissions are:

> test@google.com
	Encrypt
```

# Enclave

If the server is running inside an enclave, you can, and you should check its trustworthiness. See [saas](saas.md) for more details.

To do so:

```sh
$ cosmian_kms_cli trust /tmp
The base64 encoded quote has been saved at "/tmp/quote.raw"
The quote (structured) has been saved at "/tmp/quote.struct"
The ssl certificate has been saved at "/tmp/ssl.cert"
The sgx manifest has been saved at "/tmp/manifest.sgx"
The remote attestation has been saved at "/tmp/remote_attestation"

You can check all these files manually.

Proceed with some automatic checks:
... Remote attestation checking Ok
... MR enclave checking Ok
... MR signer checking Ok
... Quote checking Ok
... Date checking Ok
... Quote report data (manifest, kms certificates and nonce) checking Ok
```

This command proceeds the remote attestation for you.
