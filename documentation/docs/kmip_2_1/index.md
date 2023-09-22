The Cosmian KMS server supports a restricted set of the KMIP 2.1 protocol.

The Key Management Interoperability Protocol Specification Version 2.1 and Key Management Interoperability Protocol Profiles Version 2.1 are [OASIS](https://www.oasis-open.org/) Standards.

The goal of the OASIS KMIP is to define a single, comprehensive protocol for communication between encryption systems and a broad range of new and legacy enterprise applications, including email, databases, and storage devices. By removing redundant, incompatible key management processes, KMIP provides better data security while at the same time reducing expenditures on multiple products.

KMIP is a massive specification, and support is limited to the requirements of Cosmian advanced cryptography. Although the KMS server functionalities evolve quickly to support the growing demand of customers, the Cosmian KMS server, like most KMS servers, is in no way claiming to be a complete solution for all cryptographic objects and operations.

### Objects tagging extension

The Cosmian KMS server supports the tagging of objects. Tags are arbitrary strings that can be attached to objects. Tags can be used to group objects together, and to find objects for most operations, such as export, import, encrypt, decrypt, etc.

In addition, the KMS server will automatically add a system tag to objects based on the object type:

- `_sk`: for a private key
- `_pk`: for a public key
- `_kk`: for a symmetric key
- `_uk`: for a Covercrypt user decryption key
- `_cert`: for a X509 certificate

Since there is no provision in the KMIP 2.1 specification for tagging. The Cosmian KMS server implements tagging using the following KMIP 2.1 extensions:

1. When `Attributes` are passed as part of the KMIP operation, such as in the `Create`, `Create Key Pair`, `Locate`, and `Import` operations, the tags are passed as `VendorAttributes` with the vendor identification `Cosmian` and attribute name `tag`. The value is the serialization of the tags as a JSON array of strings.

2. When unique identifiers are passed as part of the KMIP operation, such as in the `Encrypt`, `Decrypt`, `Get`, `Get Attributes`, `Revoke`, and `Destroy` operations, the tags are in the unique identifier itself as a serialized JSON array e.g. `[ "tag1", "tag2" ]`.

### Example API calls

Querying the KMS server is normally done using the [ckms](../cli/cli.md) command line interface or one of the [Cloudproof libraries](https://docs.cosmian.com/cloudproof_encryption/application_level_encryption/).

The following KMIP TTLV JSON examples are provided for reference only.

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
    Server response: the unique identifier of the created key

=== "Get a key"

    ```json
    {
    "tag": "Get",
    "type": "Structure",
    "value": [
        {
        "tag": "UniqueIdentifier",
        "type": "TextString",
        "value": "eb9c5a0d-afa3-4d06-8673-3dc51431268f"
        }
    ]
    }
    ```
    Server response : The KMIP TTLV JSON of the exported key

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
    const locatePayload = {
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
