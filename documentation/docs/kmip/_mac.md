#### Specification

This operation requests the server to perform a Message Authentication Code (MAC) operation on provided data using a specified MAC key and algorithm.
The operation can be performed in a single request or as a series of requests for long data streams or by-parts cryptographic operations.

The response contains the MAC value or correlation value for streamed operations.

When a stream or by-parts operation is requested:

- The server SHALL create a unique identifier, called correlation value if Init Indicator is True.
- The server SHALL expect one or more requests with the same correlation value if Init Indicator is True.
- The server SHALL return the Correlation Value in the response if Init Indicator is True.
- The server SHALL use the Correlation Value for subsequent MAC requests.
- The server SHALL close the stream or by-parts operation when Final Indicator is True.

#### Implementation

The Cosmian KMS server supports the following MAC algorithms:

- HMAC-SHA256
- HMAC-SHA384
- HMAC-SHA512

For the complete list of supported MAC algorithms, please check the [algorithms page](../algorithms.md).

#### Example - Simple MAC

Computing MAC with SHA3-512 using a MAC key.

Corresponding [Cosmian CLI](../kms_clients/index.md) command:

```bash
cosmian kms mac --mac-key-id 027cced1-ff2b-4bd3-a200-db1041583bdc --algorithm sha3-512 --data 0011223344556677889900
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
          "tag": "Data",
          "type": "ByteString",
          "value": "F91DDB96D12CF8FAB0AA72224836D3F5F659A6634E3508A7C31DBC3727D2030254C57AD90AA5FB7F27FB3AAFABEAEB1204E4AF62BA2DE44E33E761B2C39DBACA"
        }
      ]
    }
    ```

#### Example - Stream MAC

Computing MAC for a large file in multiple parts using SHA3-512.

Corresponding [Cosmian CLI](../kms_clients/index.md) commands:

```bash
# First part with init indicator
cosmian kms mac --mac-key-id 027cced1-ff2b-4bd3-a200-db1041583bdc --algorithm sha3-512 --data 0011223344556677889900 -i
# Middle part using correlation value
cosmian kms mac --mac-key-id 027cced1-ff2b-4bd3-a200-db1041583bdc --algorithm sha3-512 --correlation-value F91DDB96D12CF8FAB0AA72224836D3F5F659A6634E3508A7C31DBC3727D2030254C57AD90AA5FB7F27FB3AAFABEAEB1204E4AF62BA2DE44E33E761B2C39DBACA --data 0011223344556677889900
# Final part with final indicator
cosmian kms mac --mac-key-id 027cced1-ff2b-4bd3-a200-db1041583bdc --algorithm sha3-512 --correlation-value 51A2F7FCA8DECFC106031BE935F28F6EEE7E3850BCDB9D9B41B0F623146D7F51E399FC8F76A8B14EB71463DB0F6D421EF431E33F8CE1897FF988237C890C808F -f --data 0011223344556677889900
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
          "value": "F91DDB96D12CF8FAB0AA72224836D3F5F659A6634E3508A7C31DBC3727D2030254C57AD90AA5FB7F27FB3AAFABEAEB1204E4AF62BA2DE44E33E761B2C39DBACA"
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
          "value": "51A2F7FCA8DECFC106031BE935F28F6EEE7E3850BCDB9D9B41B0F623146D7F51E399FC8F76A8B14EB71463DB0F6D421EF431E33F8CE1897FF988237C890C808F"
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
          "tag": "Data",
          "type": "ByteString",
          "value": "511BDAFDB2D059BD94FC72B8301ABF01DB9E02127420AED072B891A83952B88063DF3470225ACC6D46AD503E5E86B16BAEB581F218A148472120A9B541E1AF5D"
        }
      ]
    }
    ```
