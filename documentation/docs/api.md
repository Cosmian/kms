## Authentication

The KMS server provides an authentication system using access tokens (signed JWT) compatible with Auth0.

The authority domain is configured on the server using the option:

```
--auth0-authority-domain <AUTH0_AUTHORITY_DOMAIN>
    Enable the use of Auth0 by specifying the delegated authority domain configured on Auth0
    
    [env: KMS_AUTH0_AUTHORITY_DOMAIN=]
```


access, through [Access Tokens](https://auth0.com/docs/secure/tokens#access-tokens).

The access token is available through your Cosmian account. Please refer to: [console.cosmian.com](https://console.cosmian.com/secret-token).

A valid access token is required to access the KMS API. The token must be carried in HTTP header `Authorization`.

## Query using SDK

It's probably more convenient to query the KMS using a SDK due to the specificity of the KMIP format. Please, refer to [operations](kmip_2_1/operations.md) to learn how to perform queries using a KMS client SDK.

## Query using the KMS-CLI

[Read CLI](./cli.md){ .md-button }

## Query using server's API

The server implements the [JSON Profile](https://docs.oasis-open.org/kmip/kmip-profiles/v2.1/os/kmip-profiles-v2.1-os.html#_Toc32324415) of the KMIP 2.1 specifications.

Direct request can be performed by using the HTTP POST method on the `/kmip/2_1` endpoint on the server.
The parameters and the returned data of the query are a JSON containing TTLV serialized data.

You can get the kms server version using `/version` endpoint.

Examples in `bash` and `javascript` are provided below.

```

=== "javascript"

    The Javascript instructions below give some example on how the operations can be used to interact with the KMS from the client side :

    ``` javascript
    import fetch from "node-fetch";

    const url = "http://localhost:9998/kmip/2_1";

    const importPayload = {
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
                "value" : "6279746573"
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
    // Server response : Upserting object of type: SymmetricKey, with uid: unique_identifier

    const createPayload = {
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
    // Server response : Created KMS Object of type SymmetricKey with id eb9c5a0d-afa3-4d06-8673-3dc51431268f

    const getPayload = {
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
    // Server response : Retrieved Object: SymmetricKey with id eb9c5a0d-afa3-4d06-8673-3dc51431268f

    const encryptPayload = {
    "tag": "Encrypt",
    "type": "Structure",
    "value": [
        {
        "tag": "UniqueIdentifier",
        "type": "TextString",
        "value": "eb9c5a0d-afa3-4d06-8673-3dc51431268f"
        },
        {
        "tag": "IvCounterNonce",
        "type": "ByteString",
        "value": "747765616b56616c7565"
        }
    ]
    }
    // Server response : POST /kmip. Request: "Encrypt"

    const decryptPayload = {
    "tag": "Decrypt",
    "type": "Structure",
    "value": [
        {
        "tag": "UniqueIdentifier",
        "type": "TextString",
        "value": "eb9c5a0d-afa3-4d06-8673-3dc51431268f"
        },
        {
        "tag": "IvCounterNonce",
        "type": "ByteString",
        "value": "747765616b56616c7565"
        }
    ]
    }
    // Server response : POST /kmip. Request: "Decrypt"

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
