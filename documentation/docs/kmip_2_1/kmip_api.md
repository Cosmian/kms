The easiest way to call the KMIP API is to use the `ckms` [command line interface](./cli/cli.md)
or one of the Cosmian [cloudproof libraries](https://github.com/Cosmian) which provide wrapper calls in the corresponding language.

When posting directly to the server, the client must build the JSON TTLV messages as described in the KMIP 2.1 specification,
and issue a POST call to the `/kmip/2_1` endpoint.

Building the JSON TTLV messages is a complex task and the easiest way to get started is to use the `ckms` CLI
in debug mode to print the corresponding request and response messages.
The debug mode is activated by setting the `RUST_LOG` environment variable to `cosmian_kms_client::kms_rest_client=debug`.

**Example**

This creates a (default AES 256) symmetric key which will be tagged with the string `myKey`.

```bash
RUST_LOG="cosmian_kms_client::kms_rest_client=debug" \
ckms sym keys create --tag myKey 
```

The CLI will then show the JSON TTLV requests and response:

```
2023-12-02T08:44:37.916528Z DEBUG ThreadId(01) cosmian_kms_client::kms_rest_client: crate/client/src/kms_rest_client.rs:663: ==>
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
                  "value": "5B226D794B6579225D"
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}    
2023-12-02T08:44:37.921325Z DEBUG ThreadId(01) cosmian_kms_client::kms_rest_client: crate/client/src/kms_rest_client.rs:675: <==
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
      "value": "5dc81bb2-648f-485f-b804-c6ea45467056"
    }
  ]
}    
```

The following KMIP TTLV JSON examples are provided for reference.

=== "Import a key"

    ```json
    {
    "tag" : "Import",
    "value" : [ {
        "tag" : "UniqueIdentifier",
        "type" : "TextString",
        "value" : "unique_identifier"
    }, {
        "tag" : "ObjectType",
        "type" : "Enumeration",
        "value" : "SymmetricKey"
    }, {
        "tag" : "ReplaceExisting",
        "type" : "Boolean",
        "value" : true
    }, {
        "tag" : "KeyWrapType",
        "type" : "Enumeration",
        "value" : "AsRegistered"
    }, {
        "tag" : "Attributes",
        "value" : [ {
        "tag" : "Link",
        "value" : [ ]
        }, {
        "tag" : "ObjectType",
        "type" : "Enumeration",
        "value" : "OpaqueObject"
        } ]
    }, {
        "tag" : "Object",
        "value" : [ {
        "tag" : "KeyBlock",
        "value" : [ {
            "tag" : "KeyFormatType",
            "type" : "Enumeration",
            "value" : "TransparentSymmetricKey"
        }, {
            "tag" : "KeyValue",
            "value" : [ {
            "tag" : "KeyMaterial",
            "value" : [ {
                "tag" : "Key",
                "type" : "ByteString",
                "value" : "<HEX ENCODED BYTES>"
            } ]
            } ]
        }, {
            "tag" : "CryptographicAlgorithm",
            "type" : "Enumeration",
            "value" : "AES"
        }, {
            "tag" : "CryptographicLength",
            "type" : "Integer",
            "value" : 256
        } ]
        } ]
    } ]
    }
    ```
    Server response: the unique identifier of the imported key

=== "Create a key"

    Create a symmetric key with tag "myKey"
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
                      "value": "5B226D794B6579225D" // ["myKey"]
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
    Server response: the unique identifier of the created key
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
          "value": "ebddca55-6027-4c86-ac1f-6b38dcfd6ead"
        }
      ]
    }  
    ```

=== "Get a key"

    ```json
    {
      "tag": "Get",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "5dc81bb2-648f-485f-b804-c6ea45467056"
        },
        {
          "tag": "KeyWrapType",
          "type": "Enumeration",
          "value": "AsRegistered"
        }
      ]
    }   
    ```
    Server response : The KMIP TTLV JSON of the exported key
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
          "value": "5dc81bb2-648f-485f-b804-c6ea45467056"
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
                      "value": "59B33F36CD23AF36E85728097280B61FBF6388DDA7E93ACFC440773E148327BD"
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

=== "Encrypt"

    ```json
    {
    "tag": "Encrypt",
    "type": "Structure",
    "value": [
        {
        "tag": "UniqueIdentifier",
        "type": "TextString",
        "value": "<KEY ID>"
        },
        {
        "tag": "IvCounterNonce",
        "type": "ByteString",
        "value": "<HEX OF BYTES OF NONCE>"
        },
        {
        "tag": "Data",
        "type": "ByteString",
        "value": "<HEX OF BYTES TO ENCRYPT>"
        }
    ]
    }
    ```
    // Server response :

    ```json
    {
    "tag": "EncryptResponse",
    "type": "Structure",
    "value": [
        {
        "tag": "UniqueIdentifier",
        "type": "TextString",
        "value": "<KEY ID>"
        },
        {
        "tag": "Data",
        "type": "ByteString",
        "value": "<HEX OF ENCRYPTED BYTES>"
        }
    ]
    }
    ```

=== "Decrypt"

    ```json
    {
    "tag": "Decrypt",
    "type": "Structure",
    "value": [
        {
        "tag": "UniqueIdentifier",
        "type": "TextString",
        "value": "<KEY ID>"
        },
        {
        "tag": "IvCounterNonce",
        "type": "ByteString",
        "value": "<HEX OF BYTES OF NONCE>"
        },
        {
        "tag": "Data",
        "type": "ByteString",
        "value": "<HEX OF BYTES TO DECRYPT>"
        }
    ]
    }
    ```
    Server response:

    ```json
    {
    "tag": "DecryptResponse",
    "type": "Structure",
    "value": [
        {
        "tag": "UniqueIdentifier",
        "type": "TextString",
        "value": "<KEY ID>"
        },
        {
        "tag": "Data",
        "type": "ByteString",
        "value": "<HEX OF DECRYPTED BYTES>"
        }
    ]
    }
    ```

=== "Locate"

    ```json
    {
    "tag": "Locate",
    "type": "Structure",
    "value": [
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
            "tag": "KeyFormatType",
            "type": "Enumeration",
            "value": "TransparentSymmetricKey"
            },
            {
            "tag": "Link",
            "type": "Structure",
            "value": []
            },
            {
            "tag": "ObjectType",
            "type": "Enumeration",
            "value": "SymmetricKey"
            }
        ]
        }
    ]
    }
    ```

    Server Response: the list of located object unique identifiers
