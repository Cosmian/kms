# Cosmian KMS CLI

Cosmian has designed a command line to use the KMS in order to manage keys, encrypt or decrypt data.

This CLI supports several crypto-systems listed below:
- [X] Attribute-Based Encryption
- [X] Cover Crypt
- [ ] To be continued....

## Compiling

```
cargo run
```

## Usage

First of all, you need to specify the `kms.json` with the `kms_server_url` and your `kms_access_token` such as:

```json
{
    "kms_server_url": "http://127.0.0.1:9998",
    "kms_access_token": "MY_TOKEN"
}
```

Then:

```
KMS_CLI_CONF=kms.json kms_cli --help
```

If the server is running without Auth0, you can let `kms_access_token` empty. Indeed, the server is running without authentication in a single-user mode.

If the server is running with cached sqlcipher as the KMS database, you also need to specify `kms_database_secret`. The first time, your organisation uses the KMS, you will run the following command to get the `kms_database_secret`. Save it because the KMS won't remember it.

```
KMS_CLI_CONF=kms.json kms_cli configure
```

### Attribute Based Encryption / Cover Crypt

You can perform the following ABE operations by taking advantage of the KMS.

__On master keys__

- `init` Generate a new master key pair
- `rotate` Rotate an attribute 

__On user keys__

- `new` Generate a decrypt key for a new user
- `revoke` Revoke a user decryption key
- `destroy` Remove the user decryption key from the kms

__On user data__

- `encrypt` Encrypt data using the public key
- `decrypt` Decrypt data using the user decryption key

For more details, run:
```
kms_cli abe --help
```

### Permissions

You can perform the following operations concerning to the users-to-objects permissions.

- `add` Add an access authorization for an object to a user
- `list` List granted access authorizations for an object
- `owned` List objects owned by the current user
- `remove` Remove an access authorization for an object to a user
- `shared` List objects shared for the current user

### Quote

If the KMS server is runnning inside an enclave, you can and should verify its trustworthiness.

To do so, use `trust` subcommand. Doing that, the `cli` will: 

- Ask the kms server to generate a quote containing the public certificate of the kms server, a nonce (a randomly generated string to make the quote unique each time) and the SGX manifest
- Send the quote to Azure Microsoft to proceed a remote attestation
- Proceed some trust checks
- Export various files on your filesystem to let you manually verify them. 

From [gramine docs](https://gramine.readthedocs.io/en/latest/sgx-intro.html#term-sgx-quote), you can read: "*The SGX quote is the proof of trustworthiness of the enclave and is used during Remote Attestation. The attesting enclave generates the enclave-specific SGX Report, sends the request to the Quoting Enclave using Local Attestation, and the Quoting Enclave returns back the SGX quote with the SGX report embedded in it. The resulting SGX quote contains the enclave’s measurement, attributes and other security-relevant fields, and is tied to the identity of the Quoting Enclave to prove its authenticity. The obtained SGX quote may be later sent to the verifying remote party, which examines the SGX quote and gains trust in the remote enclave.*"


#### Quote report data

The report data contains attributes smartly chosen to make a decision on the trustworthiness of the enclave.

- The **ssl certificate**. This certificate is encrypted using the `mr_enclave` key. Therefore if the server is updated, the certificates will be also updated and the quote will vary. Moreover this parameter is public, so you are plenty aware when the certificate changes.
- The **nonce** to make the quote unique each time the user want a proof of trust. It uses an arbitrary and non predictable string. The kms server can't therefore send a previous verify version of the quote.
- The **manifest**. It assures you that the manifest you will read is the one the enclave is using and therefore *Cosmian* can't alter the hash of the trusted files.

#### Automatic trust checks

The cli automatically checks:
- If the kms server runs inside an sgx enclave known by *Intel*
- If the quote inside the remote attestation is the same than the quote returning by the enclave
- If the `mr_enclave` and `mr_signer` are the same between the remote attestation and the quote
- If the current time is contained into the `iat` and the `exp` time of the remote attestation
- If the quote's report data is both the same in the remote attestation and in the quote

#### Exported files

The files you can manually verify are: 

- The quote: `quote.raw` and `quote.struct`
- The manifest of the enclave containing the hashes of all trusted files and the running context (env variables, etc.): `manifest.sgx`
- The remote attestation itself: `remote_attestation`

## Testing

```
cargo test
```

A kms server is started by the test. Make sure, you don't start another one by yourself.
