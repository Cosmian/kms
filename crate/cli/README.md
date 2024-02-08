# Cosmian KMS CLI

Cosmian has designed a command line to use the KMS in order to manage keys, encrypt or decrypt data.

This CLI supports several crypto-systems listed below:

- [X] Attribute-Based Encryption
- [X] Cover Crypt

## Compiling

```sh
cargo run
```

## Usage

Create a `kms.json` file with the `kms_server_url` and your `kms_access_token` such as:

```json
{
    "accept_invalid_certs": false,
    "kms_server_url": "http://127.0.0.1:9998",
    "kms_access_token": "MY_TOKEN"
}
```

Note: `accept_invalid_certs` needs to be `true` if `kms_server_url` uses https and the server provides a self-signed ssl connection

Then from the same directory as the `kms.json` file, run:

```sh
ckms --help
```

If you wish to use a different configuration file, set its full path in the `KMS_CLI_CONF` environment variable e.g.

```sh
KMS_CLI_CONF=kms.json ckms --help
```

or you can specify the path as a command line argument, like:

```sh
ckms --conf /some/path/kms.json --help
```

If the server is running without Auth0, you can let `kms_access_token` empty. Indeed, the server is running without authentication in a single-user mode.

If the server is running with cached sqlcipher as the KMS database, you also need to specify `kms_database_secret`. The first time, your organization uses the KMS, you will run the following command to get the `kms_database_secret`. Save the output because the KMS won't remember it!

```sh
KMS_CLI_CONF=kms.json ckms new-database
```

### Attribute Based Encryption: CoverCrypt

You can perform the following ABE operations by taking advantage of the KMS.

#### On master keys

- `init` Generate a new master key pair
- `rotate` Rotate an attribute

#### On user keys

- `new` Generate a decrypt key for a new user
- `revoke` Revoke a user decryption key
- `destroy` Remove the user decryption key from the kms

#### On both user or master keys

- `export` Export a key using its uid from the KMS. The key is exported serialized in KMIP TTLV format.
- `import` Import a key to the KMS. The key to import must be serialized in KMIP TTLV format

- `export-keys` Export a raw key using its uid from the KMS. If a password is passed through and the key has been previously wrapped by the cli, the key will also be unwrapped by the cli
- `import-keys` Import a raw key to the KMS. If a password is passed through, the key will be wrapped by the cli. Otherwise, you can transparently import a plain text key or an already wrapped key done by a key the KMS doesn't know.

#### On user data

- `encrypt` Encrypt data using the public key
- `decrypt` Decrypt data using the user decryption key

For more details, run:

```sh
ckms cc --help
```

### Permissions

You can perform the following operations concerning to the users-to-objects permissions.

- `add` Add an access authorization for an object to a user
- `list` List granted access authorizations for an object
- `owned` List objects owned by the current user
- `remove` Remove an access authorization for an object to a user
- `shared` List objects shared for the current user

## Testing

```sh
cargo build --bin ckms
cargo test -p ckms
```

A KMS server is started by the test. Make sure, you don't start another one by yourself.

You can also test using a remote KMS:

```sh
cargo build --bin ckms
cargo test --features staging --no-default-features -p ckms
```
