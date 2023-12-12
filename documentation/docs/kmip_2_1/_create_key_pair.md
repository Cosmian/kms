#### Specification

This operation requests the server to generate a new public/private key pair and register the two corresponding new
Managed Cryptographic Objects.

The request contains attributes to be assigned to the objects (e.g., Cryptographic Algorithm, Cryptographic Length,
etc.). Attributes MAY be specified for both keys at the same time by specifying a Common Attributes object in the
request.

Attributes not common to both keys (e.g., Name, Cryptographic Usage Mask) MAY be specified using the Private Key
Attributes and Public Key Attributes objects in the request, which take precedence over the Common Attributes object.

For the Private Key, the server SHALL create a Link attribute of Link Type Public Key pointing to the Public Key. For
the Public Key, the server SHALL create a Link attribute of Link Type Private Key pointing to the Private Key. The
response contains the Unique Identifiers of both created objects. The ID Placeholder value SHALL be set to the Unique
Identifier of the Private Key.

#### Implementation

Please see the [supported objects](./objects.md) for the list of key pairs that can be created with this operation.

#### Example - X25519 Key Pair

Creating an X25519 key pair with the tag `MyECKeyPair`.

Please note:

- The tag is set in a JSON array and is hex-encoded before being added to the KMIP request.
- The `KeyFormatType` is set to `ECPrivateKey`.
- The `ObjectType` is set to `PrivateKey`.
- The `CryptographicAlgorithm` is set to `ECDH`.
- The `RecommendedCurve` is set to `CURVE25519`.

Corresponding `ckms` CLI command:

```shell
ckms ec keys create
```

=== "Request"

    ```json
        {
          "tag": "CreateKeyPair",
          "type": "Structure",
          "value": [
            {
              "tag": "CommonAttributes",
              "type": "Structure",
              "value": [
                {
                  "tag": "CryptographicAlgorithm",
                  "type": "Enumeration",
                  "value": "ECDH"
                },
                {
                  "tag": "CryptographicLength",
                  "type": "Integer",
                  "value": 253
                },
                {
                  "tag": "CryptographicDomainParameters",
                  "type": "Structure",
                  "value": [
                    {
                      "tag": "QLength",
                      "type": "Integer",
                      "value": 253
                    },
                    {
                      "tag": "RecommendedCurve",
                      "type": "Enumeration",
                      "value": "CURVE25519"
                    }
                  ]
                },
                {
                  "tag": "CryptographicUsageMask",
                  "type": "Integer",
                  "value": 2108
                },
                {
                  "tag": "KeyFormatType",
                  "type": "Enumeration",
                  "value": "ECPrivateKey"
                },
                {
                  "tag": "ObjectType",
                  "type": "Enumeration",
                  "value": "PrivateKey"
                },
                {
                  "tag": "VendorAttributes",
                  "type": "Structure",
                  "value": [
                    {
                      "tag": "VendorAttributes",
                      "type": "Structure",
                      "value": [
                        {
                          "tag": "VendorIdentification",
                          "type": "TextString",
                          "value": "cosmian"
                        },
                        {
                          "tag": "AttributeName",
                          "type": "TextString",
                          "value": "tag"
                        },
                        {
                          "tag": "AttributeValue",
                          "type": "ByteString",
                          //The hex encoded tag ["MyECKeyPair"]
                          "value": "5B224D7945434B657950616972225D"
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        }

    ```

=== "Response"

    ```json
        {
          "tag": "CreateKeyPairResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "PrivateKeyUniqueIdentifier",
              "type": "TextString",
              "value": "1ac18648-ab17-4755-97a3-7a24b8198b97"
            },
            {
              "tag": "PublicKeyUniqueIdentifier",
              "type": "TextString",
              "value": "52573030-0fed-4c67-b311-ceac944b2afc"
            }
          ]
        }
    ```

#### Example -Covercrypt Master Key Pair

Creating a Covercrypt master key pair with the following policy specifications which is hex-encoded before being
added to the KMIP request.

**Note**: it is much easier to use the [`ckms` CLI](../cli/cli.md) to create Covercrypt master keys where a simple
specification file can be used. Use the [debug mode](./json_ttlv_api.md) to get the hex-encoded policy from the
specifications.

For a specification file

```json
{
    "Security Level::<": [
        "Protected",
        "Confidential",
        "Top Secret::+"
    ],
    "Department": [
        "R&D",
        "HR",
        "MKG",
        "FIN"
    ]
}
```

The policy to hex-encode to the call will be:

```json
{
  "version": "V2",
  "last_attribute_value": 7,
  "dimensions": {
    "Security Level": {
      "order": [
        "Protected",
        "Confidential",
        "Top Secret"
      ],
      "attributes": {
        "Confidential": {
          "rotation_values": [
            6
          ],
          "encryption_hint": "Classic",
          "write_status": "EncryptDecrypt"
        },
        "Top Secret": {
          "rotation_values": [
            7
          ],
          "encryption_hint": "Hybridized",
          "write_status": "EncryptDecrypt"
        },
        "Protected": {
          "rotation_values": [
            5
          ],
          "encryption_hint": "Classic",
          "write_status": "EncryptDecrypt"
        }
      }
    },
    "Department": {
      "order": null,
      "attributes": {
        "MKG": {
          "rotation_values": [
            3
          ],
          "encryption_hint": "Classic",
          "write_status": "EncryptDecrypt"
        },
        "FIN": {
          "rotation_values": [
            4
          ],
          "encryption_hint": "Classic",
          "write_status": "EncryptDecrypt"
        },
        "R&D": {
          "rotation_values": [
            1
          ],
          "encryption_hint": "Classic",
          "write_status": "EncryptDecrypt"
        },
        "HR": {
          "rotation_values": [
            2
          ],
          "encryption_hint": "Classic",
          "write_status": "EncryptDecrypt"
        }
      }
    }
  }
}
```

Corresponding `ckms` CLI command:

```shell
ckms cc keys create-master-key-pair -s policy_specifications.json
```

=== "Request"

    ```json
        {
          "tag": "CreateKeyPair",
          "type": "Structure",
          "value": [
            {
              "tag": "CommonAttributes",
              "type": "Structure",
              "value": [
                {
                  "tag": "CryptographicAlgorithm",
                  "type": "Enumeration",
                  "value": "CoverCrypt"
                },
                {
                  "tag": "KeyFormatType",
                  "type": "Enumeration",
                  "value": "CoverCryptSecretKey"
                },
                {
                  "tag": "ObjectType",
                  "type": "Enumeration",
                  "value": "PrivateKey"
                },
                {
                  "tag": "VendorAttributes",
                  "type": "Structure",
                  "value": [
                    {
                      "tag": "VendorAttributes",
                      "type": "Structure",
                      "value": [
                        {
                          "tag": "VendorIdentification",
                          "type": "TextString",
                          "value": "cosmian"
                        },
                        {
                          "tag": "AttributeName",
                          "type": "TextString",
                          "value": "cover_crypt_policy"
                        },
                        {
                          "tag": "AttributeValue",
                          "type": "ByteString",
                          //The hex encoded policy
                          "value": "7B2276657273696F6E223A225632222C226C6173745F6174747269627574655F76616C7565223A372C2264696D656E73696F6E73223A7B225365637572697479204C6576656C223A7B226F72646572223A5B2250726F746563746564222C22436F6E666964656E7469616C222C22546F7020536563726574225D2C2261747472696275746573223A7B22436F6E666964656E7469616C223A7B22726F746174696F6E5F76616C756573223A5B365D2C22656E6372797074696F6E5F68696E74223A22436C6173736963222C2277726974655F737461747573223A22456E637279707444656372797074227D2C22546F7020536563726574223A7B22726F746174696F6E5F76616C756573223A5B375D2C22656E6372797074696F6E5F68696E74223A22487962726964697A6564222C2277726974655F737461747573223A22456E637279707444656372797074227D2C2250726F746563746564223A7B22726F746174696F6E5F76616C756573223A5B355D2C22656E6372797074696F6E5F68696E74223A22436C6173736963222C2277726974655F737461747573223A22456E637279707444656372797074227D7D7D2C224465706172746D656E74223A7B226F72646572223A6E756C6C2C2261747472696275746573223A7B224D4B47223A7B22726F746174696F6E5F76616C756573223A5B335D2C22656E6372797074696F6E5F68696E74223A22436C6173736963222C2277726974655F737461747573223A22456E637279707444656372797074227D2C2246494E223A7B22726F746174696F6E5F76616C756573223A5B345D2C22656E6372797074696F6E5F68696E74223A22436C6173736963222C2277726974655F737461747573223A22456E637279707444656372797074227D2C22522644223A7B22726F746174696F6E5F76616C756573223A5B315D2C22656E6372797074696F6E5F68696E74223A22436C6173736963222C2277726974655F737461747573223A22456E637279707444656372797074227D2C224852223A7B22726F746174696F6E5F76616C756573223A5B325D2C22656E6372797074696F6E5F68696E74223A22436C6173736963222C2277726974655F737461747573223A22456E637279707444656372797074227D7D7D7D7D"
                        }
                      ]
                    },
                    {
                      "tag": "VendorAttributes",
                      "type": "Structure",
                      "value": [
                        {
                          "tag": "VendorIdentification",
                          "type": "TextString",
                          "value": "cosmian"
                        },
                        {
                          "tag": "AttributeName",
                          "type": "TextString",
                          "value": "tag"
                        },
                        {
                          "tag": "AttributeValue",
                          "type": "ByteString",
                          "value": "5B5D"
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        }
    ```

=== "Response"

    ```json
        {
          "tag": "CreateKeyPairResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "PrivateKeyUniqueIdentifier",
              "type": "TextString",
              "value": "b652a48a-a48c-4dc1-bd7e-cf0e5126b7b9"
            },
            {
              "tag": "PublicKeyUniqueIdentifier",
              "type": "TextString",
              "value": "0fd1f684-156c-4ca6-adc2-0a6f4b620463"
            }
          ]
        }
    ```
