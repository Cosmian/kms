# Cosmian KMS CLI

Cosmian has designed a command line to use the KMS in order to manage keys, encrypt or decrypt data.

This CLI supports several crypto-systems listed below:
- [X] Attribute-Based Encryption
- [X] Cover Crypt

## Compiling

```
cargo run
```

## Usage

Create a `kms.json` file with the `kms_server_url` and your `kms_access_token` such as:

```json
{
    "insecure": false,
    "kms_server_url": "http://127.0.0.1:9998",
    "kms_access_token": "MY_TOKEN"
}
```

Note: `insecure` needs to be `true` if `kms_server_url` uses https and the server provides a self-signed ssl connection

Then from the same directory as the `kms.json` file, run:

```
cosmian_kms_cli --help
```

If you wish to use a different configuration file, set its full path in the `KMS_CLI_CONF` environment variable e.g.

```
KMS_CLI_CONF=kms.json cosmian_kms_cli --help
```

If the server is running without Auth0, you can let `kms_access_token` empty. Indeed, the server is running without authentication in a single-user mode.

If the server is running with cached sqlcipher as the KMS database, you also need to specify `kms_database_secret`. The first time, your organisation uses the KMS, you will run the following command to get the `kms_database_secret`. Save the output because the KMS won't remember it !

```
KMS_CLI_CONF=kms.json cosmian_kms_cli configure
```

### Attribute Based Encryption: CoverCrypt

You can perform the following ABE operations by taking advantage of the KMS.

__On master keys__

- `init` Generate a new master key pair
- `rotate` Rotate an attribute 

__On user keys__

- `new` Generate a decrypt key for a new user
- `revoke` Revoke a user decryption key
- `destroy` Remove the user decryption key from the kms

__On both user or master keys__

- `export` Export a key using its uid from the KMS. The key is exported serialized in KMIP TTLV format.
- `import` Import a key to the KMS. The key to import must be serialized in KMIP TTLV format

- `export-keys` Export a raw key using its uid from the KMS. If a password is passed through and the key has been previously wrapped by the cli, the key will also be unwrapped by the cli
- `import-keys` Import a raw key to the KMS. If a password is passed through, the key will be wrapped by the cli. Otherwise, you can transparently import a plain text key or an already wrapped key done by a key the KMS doesn't know.

__On user data__

- `encrypt` Encrypt data using the public key
- `decrypt` Decrypt data using the user decryption key

For more details, run:
```
cosmian_kms_cli cc --help
```

### Permissions

You can perform the following operations concerning to the users-to-objects permissions.

- `add` Add an access authorization for an object to a user
- `list` List granted access authorizations for an object
- `owned` List objects owned by the current user
- `remove` Remove an access authorization for an object to a user
- `shared` List objects shared for the current user

### Quote and remote attestation

If the KMS server is runnning inside an enclave, you can and should verify its trustworthiness.

To do so, use `trust` subcommand. Doing that, the `cli` will: 

- Ask the kms server to generate a quote containing the public certificate of the kms server and a nonce (a randomly generated string to make the quote unique each time)
- Send the quote to Azure Microsoft to proceed a remote attestation
- Proceed some trust checks
- Export various files on your filesystem to let you manually verify them. 

From [gramine docs](https://gramine.readthedocs.io/en/latest/sgx-intro.html#term-sgx-quote), you can read: "*The SGX quote is the proof of trustworthiness of the enclave and is used during Remote Attestation. The attesting enclave generates the enclave-specific SGX Report, sends the request to the Quoting Enclave using Local Attestation, and the Quoting Enclave returns back the SGX quote with the SGX report embedded in it. The resulting SGX quote contains the enclave’s measurement, attributes and other security-relevant fields, and is tied to the identity of the Quoting Enclave to prove its authenticity. The obtained SGX quote may be later sent to the verifying remote party, which examines the SGX quote and gains trust in the remote enclave.*"


#### Quote report data

The report data contains attributes smartly chosen to make a decision on the trustworthiness of the enclave.

- The **ssl certificate**. This certificate is encrypted using the `mr_enclave` key. Therefore if the server is updated, the certificates will be also updated and the quote will vary. Moreover this parameter is public, so you are plenty aware when the certificate changes.
- The **nonce** to make the quote unique each time the user want a proof of trust. It uses an arbitrary and non predictable string. The kms server can't therefore send a previous verify version of the quote.

#### Automatic trust checks

The cli automatically checks:
- If the kms server runs inside an sgx enclave known by *Intel*
- If the quote inside the remote attestation is the same than the quote returning by the enclave
- If the `mr_enclave` and `mr_signer` are the same between the remote attestation and the quote
- If the `mr_enclave` and `mr_signer` are the expected ones. See below.
- If the current time is contained into the `iat` and the `exp` time of the remote attestation
- If the quote's report data is both the same in the remote attestation and in the quote

#### `mr_signer`

This value enables you to verify that the KMS is running inside an enclave which belongs to *Cosmian*. Indeed this value is a `sha256` hash of the public key used to sign the enclave. 

This value will be compute by the CLI and compared against the values obtained from the quote and the remote attestation.

If the value is altered, it could mean that you are not using the *Cosmian* KMS in the *Cosmian* infrastructures. You shouldn't proceed and you should report that incident to us.

#### `mr_enclave`

This value enables you to verify that the KMS code and libraries inside the enclave are the same as the code you can read on [*Cosmian* Github](https://github.com/Cosmian).

This value is not compute by the CLI. You can get the open-sourced KMS docker, read the `mr_enclave` value from it and give it to the CLI to check it. See [README.md](../../enclave/README.md#emulate) for more details.

If the value is altered, it could mean that you are not using the KMS from *Cosmian* but a modified one. You shouldn't proceed and you should report that incident to us.

#### Exported files

The files you can manually verify are: 

- The quote: `quote.raw` and `quote.struct`
- The manifest of the enclave containing the hashes of all trusted files and the running context (env variables, etc.): `manifest.sgx`
- The remote attestation itself: `remote_attestation`
- The enclave and the ssl certificate: `enclave.pub` and `ssl.cert` 

## Testing

```
cargo build --bin cosmian_kms_cli
cargo test -p cosmian_kms_cli
```

A kms server is started by the test. Make sure, you don't start another one by yourself.

You can also test using a remote kms running inside an enclave. First, generate and start a docker as described in [README.md](../../enclave/README.md).

Then:

```
cargo build --bin cosmian_kms_cli
cargo test --features staging --no-default-features -p cosmian_kms_cli
```
