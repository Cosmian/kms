#### Specification

This operation requests the server to generate a new symmetric key or generate Secret Data as a Managed Cryptographic
Object.

The request contains information about the type of object being created, and some of the attributes to be assigned to
the object (e.g., Cryptographic Algorithm, Cryptographic Length, etc.).

The response contains the Unique Identifier of the created object. The server SHALL copy the Unique Identifier returned
in this operation into the ID Placeholder variable.

#### Implementation

This operation can be used to create a new symmetric key or a new Covercrypt user decryption key.

#### Example - Symmetric Key

Creating a 256 bit AES Symmetric Key with the tag `MySymmetricKey`.

The tags are assembled in a JSON array and encoded in hex.

The `CryptographicUsageMask` is optional.

Corresponding `ckms` CLI command:

```shell
ckms sym keys create --tag MySymmetricKey
```

=== "Request"

    ```json
        {
          "tag": "Create",
          "type": "Structure",
          "value": [
            {
              "tag": "ObjectType",
              "type": "Enumeration",
              "value": "SymmetricKey"
            },
            {
              "tag": "Attributes",
              "type": "Structure",
              "value": [
                {
                  "tag": "CryptographicAlgorithm",
                  "type": "Enumeration",
                  "value": "AES"
                },
                {
                  "tag": "CryptographicLength",
                  "type": "Integer",
                  "value": 256
                },
                {
                  "tag": "CryptographicUsageMask",
                  "type": "Integer",
                  "value": 2108
                },
                {
                  "tag": "KeyFormatType",
                  "type": "Enumeration",
                  "value": "TransparentSymmetricKey"
                },
                {
                  "tag": "ObjectType",
                  "type": "Enumeration",
                  "value": "SymmetricKey"
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
                          // ["MySymmetricKey"] in hex
                          "value": "5B224D7953796D6D65747269634B6579225D"
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
          "tag": "CreateResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "ObjectType",
              "type": "Enumeration",
              "value": "SymmetricKey"
            },
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "027cced1-ff2b-4bd3-a200-db1041583bdc"
            }
          ]
        }
    ```

#### Example - Covercrypt User Decryption Key

Creating a Covercrypt User Decryption Key with the tag `MyUserKey` and the access policy `Security Level::Confidential && (Department::FIN || Department::HR)`
(see [Create Key Pair](./_create_key_pair.md) for the corresponding master key policy).

Corresponding `ckms` CLI command:

```shell
ckms cc keys create-user-key -t "MyUserKey"\
 b652a48a-a48c-4dc1-bd7e-cf0e5126b7b9 \
 "Security Level::Confidential && (Department::FIN || Department::HR)"
```

Please note:

- The tag(s) is (are) assembled in a JSON array and encoded in hex.
- The access policy is encoded in hex.

=== "Request"

    ```json
        {
          "tag": "Create",
          "type": "Structure",
          "value": [
            {
              "tag": "ObjectType",
              "type": "Enumeration",
              "value": "PrivateKey"
            },
            {
              "tag": "Attributes",
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
                  "tag": "Link",
                  "type": "Structure",
                  "value": [
                    {
                      "tag": "Link",
                      "type": "Structure",
                      "value": [
                        {
                          "tag": "LinkType",
                          "type": "Enumeration",
                          "value": "ParentLink"
                        },
                        {
                          "tag": "LinkedObjectIdentifier",
                          "type": "TextString",
                          // the master secret key unique identifier
                          "value": "b652a48a-a48c-4dc1-bd7e-cf0e5126b7b9"
                        }
                      ]
                    }
                  ]
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
                          "value": "cover_crypt_access_policy"
                        },
                        {
                          "tag": "AttributeValue",
                          "type": "ByteString",
                          // Security Level::Confidential && (Department::FIN || Department::HR) in hex
                          "value": "5365637572697479204C6576656C3A3A436F6E666964656E7469616C20262620284465706172746D656E743A3A46494E207C7C204465706172746D656E743A3A485229"
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
                          // ["MyUserKey"] in hex
                          "value": "5B224D79557365724B6579225D"
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
          "tag": "CreateResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "ObjectType",
              "type": "Enumeration",
              "value": "PrivateKey"
            },
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "df871e79-0923-47cd-9078-bbec83287c85"
            }
          ]
        }
    ```
