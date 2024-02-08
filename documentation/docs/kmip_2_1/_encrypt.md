#### Specification

This operation requests the server to perform an encryption operation on the provided data using a Managed Cryptographic
Object as the key for the encryption operation.

The request contains information about the cryptographic parameters (mode and padding method), the data to be encrypted,
and the IV/Counter/Nonce to use. The cryptographic parameters MAY be omitted from the request as they can be specified
as associated attributes of the Managed Cryptographic Object. The IV/Counter/Nonce MAY also be omitted from the request
if the cryptographic parameters indicate that the server shall generate a Random IV on behalf of the client or the
encryption algorithm does not need an IV/Counter/Nonce. The server does not store or otherwise manage the
IV/Counter/Nonce.

If the Managed Cryptographic Object referenced has a Usage Limits attribute, then the server SHALL obtain an allocation
from the current Usage Limits value prior to performing the encryption operation. If the allocation is unable to be
obtained, the operation SHALL return with a result status of Operation Failed and result reason of Permission Denied.

The response contains the Unique Identifier of the Managed Cryptographic Object used as the key and the result of the
encryption operation.

The success or failure of the operation is indicated by the Result Status (and, if failure, the Result Reason) in the
response header.

#### Implementation

To see the list of supported cryptographic algorithms, please refer to [Supported Algorithms](../algorithms.md).

#### Example - AES GCM encryption

Encrypting the text `Hello, world!` with symmetric key `027cced1-ff2b-4bd3-a200-db1041583bd` (go to [Create](./_create.md)
to see how to create the symmetric key).

Corresponding `ckms` CLI command:

```shell
ckms sym encrypt -k 027cced1-ff2b-4bd3-a200-db1041583bd /tmp/hello_world.txt
```

*Note*: the file `/tmp/hello_world.txt` contains the text `Hello, world!`.

Please note that the response contains:

- the encrypted data
- the nonce: 12 bytes
- the authentication tag: 16 bytes

=== "Request"

    ```json
        {
          "tag": "Encrypt",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "027cced1-ff2b-4bd3-a200-db1041583bdc"
            },
            {
              "tag": "Data",
              "type": "ByteString",
              // Hello, world! as UTF-8 bytes
              "value": "48656C6C6F2C20776F726C64210A"
            }
          ]
        }

    ```

=== "Response"

    ```json
          {
            "tag": "EncryptResponse",
            "type": "Structure",
            "value": [
              {
                "tag": "UniqueIdentifier",
                "type": "TextString",
                "value": "027cced1-ff2b-4bd3-a200-db1041583bdc"
              },
              {
                "tag": "Data",
                "type": "ByteString",
                "value": "40D59A0735811135749A507FDEB3"
              },
              {
                "tag": "IvCounterNonce",
                "type": "ByteString",
                "value": "DBDD622A64F7D65E75894B1B"
              },
              {
                "tag": "AuthenticatedEncryptionTag",
                "type": "ByteString",
                "value": "50FCE680540BD3E96EFA9218A2F1009D"
              }
            ]
          }
    ```

#### Example - Covercrypt

Encrypting the text `Hello, world!` with the Covercrypt master public key `0fd1f684-156c-4ca6-adc2-0a6f4b620463`
(go to  [Create Key Pair](./_create_key_pair.md) to see how to create the mater key pair) and attributes `Security Level::Confidential && Department::FIN`.

Corresponding `ckms` CLI command:

```shell
ckms cc encrypt -k 0fd1f684-156c-4ca6-adc2-0a6f4b620463 \
 /tmp/hello_world.txt "Security Level::Confidential && Department::FIN"
```

*Note*: the file `/tmp/hello_world.txt` contains the text `Hello, world!`.

In the request, please note that the `Data` parameter contains:

- the length of the bytes of the attributes: `47 = 2F` in hexadecimal
- the attributes as bytes: `Security Level::Confidential && Department::FIN`
- the bytes to encrypt: `Hello, world!` as UTF-8 bytes

=== "Request"

    ```json
        {
          "tag": "Encrypt",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "0fd1f684-156c-4ca6-adc2-0a6f4b620463"
            },
            {
              "tag": "CryptographicParameters",
              "type": "Structure",
              "value": [
                {
                  "tag": "CryptographicAlgorithm",
                  "type": "Enumeration",
                  "value": "CoverCrypt"
                }
              ]
            },
            {
              "tag": "Data",
              "type": "ByteString",
              "value": "2F5365637572697479204C6576656C3A3A436F6E666964656E7469616C202626204465706172746D656E743A3A46494E0048656C6C6F2C20776F726C64210A"
            }
          ]
        }
    ```

=== "Response"

    ```json
        {
          "tag": "EncryptResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "0fd1f684-156c-4ca6-adc2-0a6f4b620463"
            },
            {
              "tag": "Data",
              "type": "ByteString",
              "value": "AEA6CF824612448B8445CAF46F9D987161706DAD6E43DFD1A57DD0F39869DC39A68096657A3EDC03CBC619D563744D2CC9819B6A9AB9A3893FD27F452F49A244A8CAA42279C4705D4D3A9E04D2B7887F0100D947F27D27BBD1D06F5A65087F73B8AAB617568761273282D4C14770FFCBA47200D02DDB4C48E1028DC5C50DE860A10A26E35AC405EFE6405486B56E9968594471075687D7BF6935BD003D"
            }
          ]
        }
    ```
