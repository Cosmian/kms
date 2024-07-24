AWS XKS
=======

Specs: https://github.com/aws/aws-kms-xksproxy-api-spec/blob/main/xks_proxy_api_spec.md

Code loosely inspired from https://github.com/aws-samples/aws-kms-xks-proxy/ (License Apache 2.0)

## Testing

- Start the server with XKS enabled:

```bash
cargo run --bin cosmian_kms_server -- --enable-xks-service
```

- Create an AES key using the `ckms` CLI:

```bash
ckms sym keys create --number-of-bits 256 --algorithm aes --tag "xks_test"
The symmetric key was successfully generated.
	  Unique identifier: df1d7317-85b2-4db8-9462-50b9be6dc3d1

  Tags:
    - xks_test
```

- Grant access to the key to all users:

```bash
ckms access-rights grant "*" df1d7317-85b2-4db8-9462-50b9be6dc3d1 decrypt encrypt get_attributes
```

- Clone the project at https://github.com/aws-samples/aws-kms-xksproxy-test-client

- Run the tests

On MacOS you will have to install a more recent version of bash using `brew`

```bash
PATH=<HOMEBREW>/bin:$PATH XKS_PROXY_HOST="localhost:9998" VERBOSE=-iv SCHEME= URI_PREFIX=aws 
KEY_ID=df1d7317-85b2-4db8-9462-50b9be6dc3d1 ./test-xks-proxy
```

... wherre `<HOMEBREW>` is the path to the homebrew installation directory (on MacOS).