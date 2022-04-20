## Authentication

The KMS server provides a way to authenticate access, through [Access Tokens](https://auth0.com/docs/secure/tokens#access-tokens).

The access token is available through your Cosmian account. Please refer to: [console.cosmian.com](https://console.cosmian.com/secret-token).

A valid access token is required to access the KMS REST API. The token must be carried in HTTP header `Authorization`.

## Query using SDK

It's probably more convenient to query the KMS using a SDK due to the specifity of the KMIP format. Please, refer to [operations](kimp_2_1/../kmip_2_1/operations.md) to learn how to perform queries using a KMS client SDK.

## Query using the KMS-CLI

Coming soon... ;)

## Query using server's API

The server implements the [JSON Profile](https://docs.oasis-open.org/kmip/kmip-profiles/v2.1/os/kmip-profiles-v2.1-os.html#_Toc32324415) of the KMIP 2.1 specifications.

Direct REST request can be performed by using the HTTP POST method on the `/kmip/2_1` endpoint on the server.

Examples in `bash` and `javascript` are provided below.

=== "bash"

    The bash script below gives some example on how the operations can be used to interact with the KMS from the server side :

    ```sh
    #!/bin/sh
    ​
    set -eE
    ​
    check_command_exist() {
    my_command="$1"
    if ! command -v $my_command &>/dev/null; then
        echo "$my_command could not be found"
        exit
    fi
    }
    ​
    kms_post() {
    JSON_PAYLOAD=$1
    response=$(curl -s -X POST "http://localhost:9998/kmip/2_1" -d ${JSON_PAYLOAD} -H "Content-Type: application/json")
    }
    ​
    check_command_exist jq
    check_command_exist curl
    ​
    ####
    #
    # Create an ABE Master Private key + ABE public key.
    # Remark:
    #   AttributeValue contains the ABE policy in hexadecimal-json format. As example here:
    #     {"last_attribute":9,"max_attribute":100,"store":{"Entity":[["377","378","379"],false],"Country":[["france","germany","italy","hungary","spain","belgium"],false]},"attribute_to_int":{"Country::spain":[8],"Country::belgium":[9],"Entity::379":[3],"Entity::378":[2],"Country::italy":[6],"Entity::377":[1],"Country::france":[4],"Country::hungary":[7],"Country::germany":[5]}}
    kms_post '{"tag":"CreateKeyPair","type":"Structure","value":[{"tag":"CommonAttributes","type":"Structure","value":[{"tag":"CryptographicAlgorithm","type":"Enumeration","value":"ABE"},{"tag":"KeyFormatType","type":"Enumeration","value":"AbeMasterSecretKey"},{"tag":"Link","type":"Structure","value":[]},{"tag":"ObjectType","type":"Enumeration","value":"PrivateKey"},{"tag":"VendorAttributes","type":"Structure","value":[{"tag":"VendorAttributes","type":"Structure","value":[{"tag":"String","type":"TextString","value":"cosmian"},{"tag":"String","type":"TextString","value":"abe_attributes"},{"tag":"String","type":"TextString","value":"abe_policy"},{"tag":"String","type":"TextString","value":"abe_access_policy"},{"tag":"String","type":"TextString","value":"abe_header_uid"},{"tag":"VendorIdentification","type":"TextString","value":"cosmian"},{"tag":"AttributeName","type":"TextString","value":"abe_policy"},{"tag":"AttributeValue","type":"ByteString","value":"7B226C6173745F617474726962757465223A392C226D61785F617474726962757465223A3130302C2273746F7265223A7B22456E74697479223A5B5B22333737222C22333738222C22333739225D2C66616C73655D2C22436F756E747279223A5B5B226672616E6365222C226765726D616E79222C226974616C79222C2268756E67617279222C22737061696E222C2262656C6769756D225D2C66616C73655D7D2C226174747269627574655F746F5F696E74223A7B22436F756E7472793A3A737061696E223A5B385D2C22436F756E7472793A3A62656C6769756D223A5B395D2C22456E746974793A3A333739223A5B335D2C22456E746974793A3A333738223A5B325D2C22436F756E7472793A3A6974616C79223A5B365D2C22456E746974793A3A333737223A5B315D2C22436F756E7472793A3A6672616E6365223A5B345D2C22436F756E7472793A3A68756E67617279223A5B375D2C22436F756E7472793A3A6765726D616E79223A5B355D7D7D"}]}]}]}]}'
    private_key_uid=$(echo $response | jq -r .value[0].value)
    # Response example: it contains the UIDs of ABE Master Private key and ABE public key
    # {"tag":"CreateKeyPairResponse","type":"Structure","value":[{"tag":"PrivateKeyUniqueIdentifier","type":"TextString","value":"769d77a9-28fa-4ccd-b5d8-b03d74f0a001"},{"tag":"PublicKeyUniqueIdentifier","type":"TextString","value":"53e950e8-4e87-4001-87dd-8dd955a8156a"}]}
    ​
    ####
    #
    # Create an ABE user decryption key
    # Remark:
    #   this user has its own access policy in hexadecimal-json format embbeded in the decryption key:
    #     {"And":[{"Attr":"Entity::377"},{"Attr":"Country::france"}]}
    #   the request contains the reference of the ABE Master Private key
    kms_post "{\"tag\":\"Create\",\"type\":\"Structure\",\"value\":[{\"tag\":\"ObjectType\",\"type\":\"Enumeration\",\"value\":\"PrivateKey\"},{\"tag\":\"Attributes\",\"type\":\"Structure\",\"value\":[{\"tag\":\"CryptographicAlgorithm\",\"type\":\"Enumeration\",\"value\":\"ABE\"},{\"tag\":\"KeyFormatType\",\"type\":\"Enumeration\",\"value\":\"AbeUserDecryptionKey\"},{\"tag\":\"Link\",\"type\":\"Structure\",\"value\":[{\"tag\":\"Link\",\"type\":\"Structure\",\"value\":[{\"tag\":\"LinkType\",\"type\":\"Enumeration\",\"value\":\"ParentLink\"},{\"tag\":\"LinkedObjectIdentifier\",\"type\":\"TextString\",\"value\":\"${private_key_uid}\"}]}]},{\"tag\":\"ObjectType\",\"type\":\"Enumeration\",\"value\":\"PrivateKey\"},{\"tag\":\"VendorAttributes\",\"type\":\"Structure\",\"value\":[{\"tag\":\"VendorAttributes\",\"type\":\"Structure\",\"value\":[{\"tag\":\"String\",\"type\":\"TextString\",\"value\":\"cosmian\"},{\"tag\":\"String\",\"type\":\"TextString\",\"value\":\"abe_attributes\"},{\"tag\":\"String\",\"type\":\"TextString\",\"value\":\"abe_policy\"},{\"tag\":\"String\",\"type\":\"TextString\",\"value\":\"abe_access_policy\"},{\"tag\":\"String\",\"type\":\"TextString\",\"value\":\"abe_header_uid\"},{\"tag\":\"VendorIdentification\",\"type\":\"TextString\",\"value\":\"cosmian\"},{\"tag\":\"AttributeName\",\"type\":\"TextString\",\"value\":\"abe_access_policy\"},{\"tag\":\"AttributeValue\",\"type\":\"ByteString\",\"value\":\"7B22416E64223A5B7B2241747472223A22456E746974793A3A333737227D2C7B2241747472223A22436F756E7472793A3A6672616E6365227D5D7D\"}]}]}]}]}"
    user_decryption_key_id=$(echo $response | jq -r .value[1].value)
    # Response examle: it contains the UID of the user decryption key
    # {"tag":"CreateResponse","type":"Structure","value":[{"tag":"ObjectType","type":"Enumeration","value":"PrivateKey"},{"tag":"UniqueIdentifier","type":"TextString","value":"78b5d54d-01b0-464e-a36f-3ec5db5216ef"}]}
    ​
    ####
    #
    # Import a symmetric key. This key has been wrapped outside the KMS with AES256-GCM (nonce appears in `IVCounterNonce`)
    # Remark:
    #   UID is generated by the client and replace existing KMS-object (if found)
    wrapped_symmetric_key_id="9962bbbe-6525-423d-bf66-71c28fe6f6b9"
    kms_post "{\"tag\":\"Import\",\"type\":\"Structure\",\"value\":[{\"tag\":\"UniqueIdentifier\",\"type\":\"TextString\",\"value\":\"${wrapped_symmetric_key_id}\"},{\"tag\":\"ObjectType\",\"type\":\"Enumeration\",\"value\":\"SymmetricKey\"},{\"tag\":\"ReplaceExisting\",\"type\":\"Boolean\",\"value\":true},{\"tag\":\"KeyWrapType\",\"type\":\"Enumeration\",\"value\":\"AsRegistered\"},{\"tag\":\"Attributes\",\"type\":\"Structure\",\"value\":[{\"tag\":\"CryptographicAlgorithm\",\"type\":\"Enumeration\",\"value\":\"AES\"},{\"tag\":\"Link\",\"type\":\"Structure\",\"value\":[]},{\"tag\":\"ObjectType\",\"type\":\"Enumeration\",\"value\":\"SymmetricKey\"}]},{\"tag\":\"Object\",\"type\":\"Structure\",\"value\":[{\"tag\":\"KeyBlock\",\"type\":\"Structure\",\"value\":[{\"tag\":\"KeyFormatType\",\"type\":\"Enumeration\",\"value\":\"TransparentSymmetricKey\"},{\"tag\":\"KeyValue\",\"type\":\"ByteString\",\"value\":\"8C74023889DA771591F06A6C23A5BB1B7A8E4C7FE4BDF3D2C66B3A6709BC51CF80E9EBADE25D29E3130EF211ED4BAA5B\"},{\"tag\":\"CryptographicAlgorithm\",\"type\":\"Enumeration\",\"value\":\"AES\"},{\"tag\":\"CryptographicLength\",\"type\":\"Integer\",\"value\":256},{\"tag\":\"KeyWrappingData\",\"type\":\"Structure\",\"value\":[{\"tag\":\"WrappingMethod\",\"type\":\"Enumeration\",\"value\":\"Encrypt\"},{\"tag\":\"IVCounterNonce\",\"type\":\"ByteString\",\"value\":\"498F84E0E1BB74792C00F5B1\"}]}]}]}]}"
    ​
    ####
    #
    # Get KMS objects: ABE Public key, Abe User decryption key or wrapped symmetric key
    # Remark:
    #
    kms_post "{\"tag\":\"Get\",\"type\":\"Structure\",\"value\":[{\"tag\":\"UniqueIdentifier\",\"type\":\"TextString\",\"value\":\"${wrapped_symmetric_key_id}\"},{\"tag\":\"KeyFormatType\",\"type\":\"Enumeration\",\"value\":\"AbeMasterPublicKey\"}]}"
    echo "Wrapped symmetric key: $response"
    ​
    kms_post "{\"tag\":\"Get\",\"type\":\"Structure\",\"value\":[{\"tag\":\"UniqueIdentifier\",\"type\":\"TextString\",\"value\":\"${private_key_uid}\"},{\"tag\":\"KeyFormatType\",\"type\":\"Enumeration\",\"value\":\"AbeUserDecryptionKey\"}]}"
    echo "ABE Master private key: $response"
    ​
    kms_post "{\"tag\":\"Get\",\"type\":\"Structure\",\"value\":[{\"tag\":\"UniqueIdentifier\",\"type\":\"TextString\",\"value\":\"${user_decryption_key_id}\"},{\"tag\":\"KeyFormatType\",\"type\":\"Enumeration\",\"value\":\"TransparentSymmetricKey\"}]}"
    echo "ABE User decryption key: $response"
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
