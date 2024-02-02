#### Specification

This operation requests that the server returns a Managed Object specified by its Unique Identifier, together with its
attributes.

The Key Format Type, Key Wrap Type, Key Compression Type and Key Wrapping Specification SHALL have the same semantics as
for the Get operation. If the Managed Object has been Destroyed then the key material for the specified managed object
SHALL not be returned in the response.

The server SHALL copy the Unique Identifier returned by this operations into the ID Placeholder variable.

#### Implementation

The Export operation - contrarily to the `Get`operation - allows exporting objects which have been revoked or
destroyed.
When an object is destroyed, the key material cannot be exported anymore; only the attributes are returned.

To be able to export an Object the user must have the `export` permission on the object or be the object owner.

Key wrapping and unwrapping on export is supported for all keys. Please check the [algorithms page](../algorithms.md)
for more details.

For the list of supported key formats, please check the [formats page](./formats.md).

#### Examples -  Check `Get`

An export example is provided below but it is in every point similar to the `Get` operation save for the
name of the operation. To run `Export` instead of `Get` with he `ckms` CLI, pass the `--allow-revoked` flag on the
command line.

Please check the [Get](./_get.md) page for more examples.

#### Example - Symmetric Key

Exporting a symmetric key `027cced1-ff2b-4bd3-a200-db1041583bdc` (go to [Create](./_create.md) to see how to create the
symmetric key).

Instead of using the UID of the key, we can use the unique tag of the key `MySymmetricKey`. The key must be uniquely
identified. It is possible to use multiple tags to identify a key; for instance symmetric keys automatically get a
*system* tag `_kk`. See [tagging](./tagging.md) for more information on tags.

The response is in `Raw`format, the default format for symmetric keys specified by KMIP 2.1; see the [formats page](.
/formats.md) for details.

Corresponding `ckms` CLI command:

```bash
ckms sym keys export -t "MySymmetricKey" /tmp/sym_key.json  --allow-revoked
```

=== "Request"

    ```json
        {
          "tag": "Export",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "[\"MySymmetricKey\"]"
            },
            {
              "tag": "KeyWrapType",
              "type": "Enumeration",
              "value": "AsRegistered"
            }
          ]
        }

    ```

=== "Response"

    ```json
        {
          "tag": "GetResponse",
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
            },
            {
              "tag": "Object",
              "type": "Structure",
              "value": [
                {
                  "tag": "KeyBlock",
                  "type": "Structure",
                  "value": [
                    {
                      "tag": "KeyFormatType",
                      "type": "Enumeration",
                      "value": "Raw"
                    },
                    {
                      "tag": "KeyValue",
                      "type": "Structure",
                      "value": [
                        {
                          "tag": "KeyMaterial",
                          "type": "ByteString",
                          "value": "0B3E539510BABD291BB9FEC2A390C833B05465F33374575CE4AAFFABD5E93020"
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
                            }
                          ]
                        }
                      ]
                    },
                    {
                      "tag": "CryptographicAlgorithm",
                      "type": "Enumeration",
                      "value": "AES"
                    },
                    {
                      "tag": "CryptographicLength",
                      "type": "Integer",
                      "value": 256
                    }
                  ]
                }
              ]
            }
          ]
        }
    ```
