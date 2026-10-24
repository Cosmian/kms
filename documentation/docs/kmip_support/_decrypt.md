# Decrypt

## Specification

This operation requests the server to perform a decryption operation on the provided data using a Managed Cryptographic
Object as the key for the decryption operation.

The request contains information about the cryptographic parameters (mode and padding method), the data to be decrypted,
and the IV/Counter/Nonce to use. The cryptographic parameters MAY be omitted from the request as they can be specified
as associated attributes of the Managed Cryptographic Object. The initialization vector/counter/nonce MAY also be
omitted from the request if the algorithm does not use an IV/Counter/Nonce.

The response contains the Unique Identifier of the Managed Cryptographic Object used as the key and the result of the
decryption operation.

The success or failure of the operation is indicated by the Result Status (and if failure, the Result Reason) in the
response header.

## Implementation

Decryption is supported for symmetric keys, private keys, and OpenPGP secret keys (`PGPKey`, non-FIPS mode). To see the list of supported cryptographic algorithms, please refer to [Supported Algorithms](../certifications_and_compliance/cryptographic_algorithms/algorithms.md).

AEAD tags (GCM, ChaCha20-Poly1305) must be 12 to 16 bytes long, and match the `Tag Length` when the request gives one;
a shorter or mismatching tag fails with `Invalid Field`, and an invalid declared `Tag Length` with
`Bad Cryptographic Parameters`. A mode that needs an IV fails with `Missing Initialization Vector` when none is sent;
an empty IV means an all-zero IV, and an IV of the wrong length fails with `Invalid Field`.

A key in the wrong state fails with `Wrong Key Lifecycle State`, a usable object of the wrong type with
`Invalid Object Type`, and a key whose Cryptographic Usage Mask lacks `Decrypt` with
`Incompatible Cryptographic Usage Mask`.

### Multi-part decryption

Symmetric decryption (AES ECB, CBC, GCM and, in non-FIPS mode, ChaCha20-Poly1305) can be split into parts: the first
request sets `Init Indicator`, the following ones send back the returned `Correlation Value`, and the last one sets
`Final Indicator`. Cryptographic Parameters, IV and Additional Authenticated Data are fixed by the first part; a later
part that changes them fails with `Invalid Field`. `Init Indicator` and `Final Indicator` together without a
`Correlation Value` make a single-part request. The `Correlation Value` is bound to the user, the operation and the
key. The AEAD tag may be sent on the first or the final part; a final part with no tag fails with `Invalid Field`.
Non-symmetric keys, HSM keys, XTS, key wrapping, GCM-SIV and pure ChaCha20 fail with `Feature Not Supported`.

!!! warning "Plaintext is unauthenticated until the final part succeeds"
    As the KMIP profiles require, every part returns its plaintext at once. With an AEAD cipher the
    authentication tag is only checked by the final part, so the plaintext of the earlier parts is
    unauthenticated and may have been tampered with. Discard everything received if the final part fails, or
    use single-part decryption, which checks the tag before returning any plaintext. Any failed part ends the
    operation.

Open multi-part operations are kept in server memory: at most 1024 (64 per user), each abandoned after 5 idle minutes
or one hour in total, and when its key is destroyed or revoked as compromised. Multi-part Sign and Signature Verify
buffer their input, within 16 MiB per operation, 64 MiB per user and 256 MiB in total. Going beyond any of these
limits fails with `Server Limit Exceeded`.

## Example - AES GCM decryption

Decrypting the text `Hello, world!` with symmetric key `027cced1-ff2b-4bd3-a200-db1041583bd` (go to [Create](./_create.md) to see how to create the symmetric key).

Instead of using the UID of the key, we can use the unique tag of the key `MySymmetricKey`. The key must be uniquely
identified. It is possible to use multiple tags to identify a key; for instance symmetric keys automatically get a
*system* tag `_kk`. See [tagging](./tagging.md) for more information on tags.

Corresponding [KMS CLI](../kms_clients/index.md) command:

```shell
ckms sym decrypt /tmp/encrypted.bin -t "MySymmetricKey"
```

where `/tmp/encrypted.bin` contains the a concatenation of the the nonce, the encrypted and the authentication tag
in that order.

The JSON TTLV request the same information as in the [`Encrypt` Response](./_encrypt.md):

- the encrypted data
- the nonce: 12 bytes
- the authentication tag: 16 bytes

=== "Request"

    ```json
    {
      "tag": "Decrypt",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "[\"MySymmetricKey\"]"
        },
        {
          "tag": "Data",
          "type": "ByteString",
          "value": "40D59A0735811135749A507FDEB3"
        },
        {
          "tag": "IVCounterNonce",
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

=== "Response"

    ```json
    {
      "tag": "DecryptResponse",
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
          "value": "48656C6C6F2C20776F726C64210A"
        }
      ]
    }
    ```

## Example - Covercrypt

Decrypting the text `Hello, world!` with Covercrypt user decryption key `df871e79-0923-47cd-9078-bbec83287c85` (go
to [Create](./_create.md) to see how to create the Covercrypt user decryption key).

Instead of using the UID of the key, we can use the unique tag of the key `MyUserKey`. The key must be uniquely
identified. It is possible to use multiple tags to identify a key; for instance Covercrypt user decryption keys
automatically get a *system* tag `_uk`. See [tagging](./tagging.md) for more information on tags.

Corresponding [KMS CLI](../kms_clients/index.md) command:

```shell
ckms cc decrypt /tmp/encrypted.bin  -t "MyUserKey"
```

=== "Request"

    ```json
    {
      "tag": "Decrypt",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "[\"MyUserKey\"]"
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
          "value": "AEA6CF824612448B8445CAF46F9D987161706DAD6E43DFD1A57DD0F39869DC39A68096657A3EDC03CBC619D563744D2CC9819B6A9AB9A3893FD27F452F49A244A8CAA42279C4705D4D3A9E04D2B7887F0100D947F27D27BBD1D06F5A65087F73B8AAB617568761273282D4C14770FFCBA47200D02DDB4C48E1028DC5C50DE860A10A26E35AC405EFE6405486B56E9968594471075687D7BF6935BD003D"
        }
      ]
    }
    ```

=== "Response"

    ```json
    {
      "tag": "DecryptResponse",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "df871e79-0923-47cd-9078-bbec83287c85"
        },
        {
          "tag": "Data",
          "type": "ByteString",
          "value": "0048656C6C6F2C20776F726C64210A"
        }
      ]
    }
    ```
