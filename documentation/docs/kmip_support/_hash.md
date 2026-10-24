# Hash

## Specification

This operation requests the server to perform a hash operation on provided data, using a specified Hashing Algorithm.
The operation can be performed in a single request or as a series of requests for long data streams or by-parts cryptographic operations.

The response contains the hashed data.

When a stream or by-parts operation is requested:

- The server SHALL create a unique identifier, called correlation value if Init Indicator is True.
- The server SHALL expect one or more requests with the same correlation value if Init Indicator is True.
- The server SHALL return the Correlation Value in the response if Init Indicator is True.
- The server SHALL use the Correlation Value for subsequent Hash requests.
- The server SHALL close the stream or by-parts operation when Final Indicator is True.

## Implementation

The Eviden KMS server supports the following hashing algorithms:

- SHA-224, SHA-256, SHA-384, SHA-512
- SHA3-224, SHA3-256, SHA3-384, SHA3-512

Other algorithms return `Feature_Not_Supported`.

For the complete list of supported hashing algorithms, please check the [algorithms page](../certifications_and_compliance/cryptographic_algorithms/algorithms.md).

A request with both `Init Indicator` and `Final Indicator` but no `Correlation Value` is a single-part request.
A single-part Hash without `Data` returns `Invalid_Field`. An unknown, expired or foreign `Correlation Value`
returns `Invalid_Correlation_Value`. The limits on open multi-part operations are described in
[Multi-part decryption](./_decrypt.md#multi-part-decryption).

## Example - Simple hash

Hashing data with SHA256.

Corresponding [KMS CLI](../kms_clients/index.md) command:

```bash
ckms hash --algorithm sha3-512 --data 0011223344556677889900
```

=== "Request"

    ```json
    {
      "tag": "Hash",
      "type": "Structure",
      "value": [
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
        },
        {
          "tag": "InitIndicator",
          "type": "Boolean",
          "value": false
        },
        {
          "tag": "FinalIndicator",
          "type": "Boolean",
          "value": false
        }
      ]
    }
    ```

=== "Response"

    ```json
    {
      "tag": "HashResponse",
      "type": "Structure",
      "value": [
        {
          "tag": "Data",
          "type": "ByteString",
          "value": "F91DDB96D12CF8FAB0AA72224836D3F5F659A6634E3508A7C31DBC3727D2030254C57AD90AA5FB7F27FB3AAFABEAEB1204E4AF62BA2DE44E33E761B2C39DBACA"
        }
      ]
    }
    ```

## Example - Stream hash

Hashing a large file in multiple parts using SHA-256. The Init response returns a 16-byte random Correlation Value;
every later part sends it back unchanged. The three parts `61`, `62`, `63` (`abc`) give SHA-256(`abc`).

Corresponding [KMS CLI](../kms_clients/index.md) command:

```bash
# First part with init indicator
ckms hash --algorithm sha256 --data 61 -i
# Middle part using correlation value
ckms hash --algorithm sha256 --correlation-value 0123456789ABCDEF0123456789ABCDEF --data 62
# Final part with final indicator
ckms hash --algorithm sha256 --correlation-value 0123456789ABCDEF0123456789ABCDEF -f --data 63
```

=== "Request 1 (Init)"

    ```json
    {
      "tag": "Hash",
      "type": "Structure",
      "value": [
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
          "value": "61"
        },
        {
          "tag": "InitIndicator",
          "type": "Boolean",
          "value": true
        },
        {
          "tag": "FinalIndicator",
          "type": "Boolean",
          "value": false
        }
      ]
    }
    ```

=== "Response 1"

    ```json
    {
      "tag": "HashResponse",
      "type": "Structure",
      "value": [
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
      "tag": "Hash",
      "type": "Structure",
      "value": [
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
          "value": "62"
        },
        {
          "tag": "CorrelationValue",
          "type": "ByteString",
          "value": "0123456789ABCDEF0123456789ABCDEF"
        },
        {
          "tag": "InitIndicator",
          "type": "Boolean",
          "value": false
        },
        {
          "tag": "FinalIndicator",
          "type": "Boolean",
          "value": false
        }
      ]
    }
    ```

=== "Response 2"

    ```json
    {
      "tag": "HashResponse",
      "type": "Structure",
      "value": [
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
      "tag": "Hash",
      "type": "Structure",
      "value": [
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
          "value": "63"
        },
        {
          "tag": "CorrelationValue",
          "type": "ByteString",
          "value": "0123456789ABCDEF0123456789ABCDEF"
        },
        {
          "tag": "InitIndicator",
          "type": "Boolean",
          "value": false
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
      "tag": "HashResponse",
      "type": "Structure",
      "value": [
        {
          "tag": "Data",
          "type": "ByteString",
          "value": "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        }
      ]
    }
    ```
