# Mac

## Specification

This operation requests the server to perform a Message Authentication Code (MAC) operation on provided data using a specified MAC key and algorithm.
The operation can be performed in a single request or as a series of requests for long data streams or by-parts cryptographic operations.

The response contains the MAC value or correlation value for streamed operations.

When a stream or by-parts operation is requested:

- The server SHALL create a unique identifier, called correlation value if Init Indicator is True.
- The server SHALL expect one or more requests with the same correlation value if Init Indicator is True.
- The server SHALL return the Correlation Value in the response if Init Indicator is True.
- The server SHALL use the Correlation Value for subsequent MAC requests.
- The server SHALL close the stream or by-parts operation when Final Indicator is True.

## Implementation

The Eviden KMS server supports the following MAC algorithms:

- HMAC-SHA-1 (NIST SP 800-131A Rev. 2 — Acceptable)
- HMAC-SHA-224 (NIST SP 800-131A Rev. 2 — Acceptable)
- HMAC-SHA-256
- HMAC-SHA-384
- HMAC-SHA-512
- HMAC-SHA3-224, HMAC-SHA3-256, HMAC-SHA3-384, HMAC-SHA3-512 (keys of algorithm `HMACSHA3224` to `HMACSHA3512` can be created)

For the complete list of supported MAC algorithms, please check the [algorithms page](../certifications_and_compliance/cryptographic_algorithms/algorithms.md).

The hash function is taken from the request `Hashing Algorithm`, else from the request `Cryptographic Algorithm`
(`HMACSHA*`; any other value returns `Bad_Cryptographic_Parameters`), else from the key's algorithm. Unsupported
hash functions return `Feature_Not_Supported`.

The key's Cryptographic Usage Mask must contain `MAC Generate` (MAC) or `MAC Verify` (MAC Verify), or the key must
have no mask at all; otherwise the request fails with `Incompatible_Cryptographic_Usage_Mask`. HMAC keys created by
the server get both bits; older HMAC keys need their mask updated. A key in the wrong state returns
`Wrong_Key_Lifecycle_State` and a usable object of the wrong type `Invalid_Object_Type`.

A request with both `Init Indicator` and `Final Indicator` but no `Correlation Value` is a single-part request.
A single-part MAC without `Data` returns `Invalid_Field`. HSM keys cannot be used for multi-part MAC
(`Feature_Not_Supported`).

### MAC Verify

MAC Verify accepts Active, Deactivated and Compromised keys. It supports multi-part requests: the `MACData` to check
may be sent on the Init or the Final part, and a missing `MACData` at the end returns `Invalid_Field`. The
`ValidityIndicator` is returned only on single-part or final responses. The comparison runs in constant time.

## Example - Simple MAC

Computing MAC with SHA3-512 using a MAC key.

!!! warning "The key must allow MAC"
    The key must have the `MAC Generate` (and, for MAC Verify, `MAC Verify`) bit in its Cryptographic Usage Mask.
    An AES key created with the default mask (see [Create](./_create.md)) does not; use an HMAC key instead.

Corresponding [KMS CLI](../kms_clients/index.md) command:

```bash
ckms mac --mac-key-id 027cced1-ff2b-4bd3-a200-db1041583bdc --algorithm sha3-512 --data 0011223344556677889900
```

=== "Request"

    ```json
    {
      "tag": "Mac",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "027cced1-ff2b-4bd3-a200-db1041583bdc"
        },
        {
          "tag": "CryptographicParameters",
          "type": "Structure",
          "value": [
            {
              "tag": "HashingAlgorithm",
              "type": "Enumeration",
              "value": "SHA3512"
            }
          ]
        },
        {
          "tag": "Data",
          "type": "ByteString",
          "value": "0011223344556677889900"
        }
      ]
    }
    ```

=== "Response"

    ```json
    {
      "tag": "MacResponse",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "027cced1-ff2b-4bd3-a200-db1041583bdc"
        },
        {
          "tag": "MACData",
          "type": "ByteString",
          "value": "F91DDB96D12CF8FAB0AA72224836D3F5F659A6634E3508A7C31DBC3727D2030254C57AD90AA5FB7F27FB3AAFABEAEB1204E4AF62BA2DE44E33E761B2C39DBACA"
        }
      ]
    }
    ```

## Example - Stream MAC

Computing MAC for a large file in multiple parts using HMAC-SHA-256. The Init response returns a 16-byte random
Correlation Value; every later part sends it back unchanged. The MAC shown is the one of the
`hmac_sha256_multi_part` test vector, computed with that vector's key.

Corresponding [KMS CLI](../kms_clients/index.md) commands:

```bash
# First part with init indicator
ckms mac --mac-key-id 027cced1-ff2b-4bd3-a200-db1041583bdc --algorithm sha256 --data 0102 -i
# Middle part using correlation value
ckms mac --mac-key-id 027cced1-ff2b-4bd3-a200-db1041583bdc --algorithm sha256 --correlation-value 0123456789ABCDEF0123456789ABCDEF --data 030405060708091011121314
# Final part with final indicator
ckms mac --mac-key-id 027cced1-ff2b-4bd3-a200-db1041583bdc --algorithm sha256 --correlation-value 0123456789ABCDEF0123456789ABCDEF -f --data 1516
```

=== "Request 1 (Init)"

    ```json
    {
      "tag": "Mac",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "027cced1-ff2b-4bd3-a200-db1041583bdc"
        },
        {
          "tag": "CryptographicParameters",
          "type": "Structure",
          "value": [
            {
              "tag": "HashingAlgorithm",
              "type": "Enumeration",
              "value": "SHA256"
            }
          ]
        },
        {
          "tag": "Data",
          "type": "ByteString",
          "value": "0102"
        },
        {
          "tag": "InitIndicator",
          "type": "Boolean",
          "value": true
        }
      ]
    }
    ```

=== "Response 1"

    ```json
    {
      "tag": "MacResponse",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "027cced1-ff2b-4bd3-a200-db1041583bdc"
        },
        {
          "tag": "CorrelationValue",
          "type": "ByteString",
          "value": "0123456789ABCDEF0123456789ABCDEF"
        }
      ]
    }
    ```

=== "Request 2 (Middle)"

    ```json
    {
      "tag": "Mac",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "027cced1-ff2b-4bd3-a200-db1041583bdc"
        },
        {
          "tag": "CryptographicParameters",
          "type": "Structure",
          "value": [
            {
              "tag": "HashingAlgorithm",
              "type": "Enumeration",
              "value": "SHA256"
            }
          ]
        },
        {
          "tag": "Data",
          "type": "ByteString",
          "value": "030405060708091011121314"
        },
        {
          "tag": "CorrelationValue",
          "type": "ByteString",
          "value": "0123456789ABCDEF0123456789ABCDEF"
        }
      ]
    }
    ```

=== "Response 2"

    ```json
    {
      "tag": "MacResponse",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "027cced1-ff2b-4bd3-a200-db1041583bdc"
        },
        {
          "tag": "CorrelationValue",
          "type": "ByteString",
          "value": "0123456789ABCDEF0123456789ABCDEF"
        }
      ]
    }
    ```

=== "Request 3 (Final)"

    ```json
    {
      "tag": "Mac",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "027cced1-ff2b-4bd3-a200-db1041583bdc"
        },
        {
          "tag": "CryptographicParameters",
          "type": "Structure",
          "value": [
            {
              "tag": "HashingAlgorithm",
              "type": "Enumeration",
              "value": "SHA256"
            }
          ]
        },
        {
          "tag": "Data",
          "type": "ByteString",
          "value": "1516"
        },
        {
          "tag": "CorrelationValue",
          "type": "ByteString",
          "value": "0123456789ABCDEF0123456789ABCDEF"
        },
        {
          "tag": "FinalIndicator",
          "type": "Boolean",
          "value": true
        }
      ]
    }
    ```

=== "Response 3"

    ```json
    {
      "tag": "MacResponse",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "027cced1-ff2b-4bd3-a200-db1041583bdc"
        },
        {
          "tag": "MACData",
          "type": "ByteString",
          "value": "C911E78196D64C30F631BB079EA37B97A95936D4DA764D6A171DF030C895ECF9"
        }
      ]
    }
    ```
