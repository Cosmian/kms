# Cosmian KMS CLI

Cosmian has designed a command line to use the KMS in order to manage keys, encrypt or decrypt data.

This CLI supports several crypto-systems listed below:
- [X] Attribute-Based Encryption
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

### Attribute Based Encryption

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

## Testing

```
cargo test
```

A kms server is started by the test. Make sure, you don't start another one by yourself.