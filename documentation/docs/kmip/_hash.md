#### Specification

This operation requests the server to perform a hash operation on provided data, using a specified Hashing Algorithm.
The operation can be performed in a single request or as a series of requests for long data streams or by-parts cryptographic operations.

The response contains the hashed data.

When a stream or by-parts operation is requested:

- The server SHALL create a unique identifier, called correlation value if Init Indicator is True.
- The server SHALL expect one or more requests with the same correlation value if Init Indicator is True.
- The server SHALL return the Correlation Value in the response if Init Indicator is True.
- The server SHALL use the Correlation Value for subsequent Hash requests.
- The server SHALL close the stream or by-parts operation when Final Indicator is True.

#### Implementation

The Cosmian KMS server supports the following hashing algorithms:

- SHA256
- SHA384
- SHA512

For the complete list of supported hashing algorithms, please check the [algorithms page](../algorithms.md).

#### Example - Simple hash

Hashing data with SHA256.

Corresponding [Cosmian CLI](../kms_clients/index.md) command:

```bash
cosmian kms hash --algorithm sha3-512 --data 0011223344556677889900
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

#### Example - Stream hash

Hashing a large file in multiple parts using SHA256.

Corresponding [Cosmian CLI](../kms_clients/index.md) command:

```bash
# First part with init indicator
cosmian kms hash --algorithm sha3-512 --data 0011223344556677889900 -i
# Middle part using correlation value
cosmian kms hash --algorithm sha3-512 --correlation-value F91DDB96D12CF8FAB0AA72224836D3F5F659A6634E3508A7C31DBC3727D2030254C57AD90AA5FB7F27FB3AAFABEAEB1204E4AF62BA2DE44E33E761B2C39DBACA --data 0011223344556677889900
# Final part with final indicator
cosmian kms hash --algorithm sha3-512 --correlation-value 51A2F7FCA8DECFC106031BE935F28F6EEE7E3850BCDB9D9B41B0F623146D7F51E399FC8F76A8B14EB71463DB0F6D421EF431E33F8CE1897FF988237C890C808F -f --data 0011223344556677889900
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
          "value": "F91DDB96D12CF8FAB0AA72224836D3F5F659A6634E3508A7C31DBC3727D2030254C57AD90AA5FB7F27FB3AAFABEAEB1204E4AF62BA2DE44E33E761B2C39DBACA"
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
          "tag": "CorrelationValue",
          "type": "ByteString",
          "value": "F91DDB96D12CF8FAB0AA72224836D3F5F659A6634E3508A7C31DBC3727D2030254C57AD90AA5FB7F27FB3AAFABEAEB1204E4AF62BA2DE44E33E761B2C39DBACA"
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
          "tag": "CorrelationValue",
          "type": "ByteString",
          "value": "51A2F7FCA8DECFC106031BE935F28F6EEE7E3850BCDB9D9B41B0F623146D7F51E399FC8F76A8B14EB71463DB0F6D421EF431E33F8CE1897FF988237C890C808F"
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
          "value": "511BDAFDB2D059BD94FC72B8301ABF01DB9E02127420AED072B891A83952B88063DF3470225ACC6D46AD503E5E86B16BAEB581F218A148472120A9B541E1AF5D"
        }
      ]
    }
    ```
