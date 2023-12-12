#### Specification

This request is used to generate a replacement key pair for an existing public/private key pair. It is analogous to the
Create Key Pair operation, except that attributes of the replacement key pair are copied from the existing key pair,
with the exception of the attributes listed in Re-key Key Pair Attribute Requirements tor.

As the replacement of the key pair takes over the name attribute for the existing public/private key pair, Re-key Key
Pair SHOULD only be performed once on a given key pair.

For both the existing public key and private key, the server SHALL create a Link attribute of Link Type Replacement Key
pointing to the replacement public and private key, respectively. For both the replacement public and private key, the
server SHALL create a Link attribute of Link Type Replaced Key pointing to the existing public and private key,
respectively.

The server SHALL copy the Private Key Unique Identifier of the replacement private key returned by this operation into
the ID Placeholder variable.

An Offset MAY be used to indicate the difference between the Initial Date and the Activation Date of the replacement key
pair. If no Offset is specified, the Activation Date and Deactivation Date values are copied from the existing key pair.
If Offset is set and dates exist for the existing key pair, then the dates of the replacement key pair SHALL be set
based on the dates of the existing key pair as follows

#### Implementation

The `Re-Key Key Pair` Operation is the main mechanism to rotate Covercrypt attributes on the Cosmian KMS Server. By
updating, through this operation, the Policy held by a Master Private Key in it Vendor Attributes, the Cosmian KMS Server
will automatically

- update the Policy held by the Master Public Key
- and re-key all non revoked User Decryption Keys holding the rotated policy attributes in a way that they will now be
  able to decrypt cipher texts encrypted with attributes before and after the rotation.

The operation has currently no other usages on the Cosmian server.

### Example - Rotate the `Security Level::Confidential` attribute

Corresponding `ckms` CLI command:

```bash
ckms cc rotate -k b652a48a-a48c-4dc1-bd7e-cf0e5126b7b9 "Security Level::Confidential"
```

Using a JSON TTLV request to rotate the `Security Level::Confidential` attribute on a Master Private Key, construct a JSON object containing
an array of the attributes that must be rotated:

```json
{
  "RotateAttributes":
    [
      "Security Level::Confidential"
    ]
}
```

Then hex encode the JSON and add it as a `VendorAttribute` with name `cover_crypt_policy_edit_action` to the `Re-Key
Key Pair` request.

The Private Key Unique Identifier of the Master Secret Key must be passed in the request.

=== "Request"

    ```json
        {
          "tag": "ReKeyKeyPair",
          "type": "Structure",
          "value": [
            {
              "tag": "PrivateKeyUniqueIdentifier",
              "type": "TextString",
              "value": "b652a48a-a48c-4dc1-bd7e-cf0e5126b7b9"
            },
            {
              "tag": "PrivateKeyAttributes",
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
                          "value": "cover_crypt_policy_edit_action"
                        },
                        {
                          "tag": "AttributeValue",
                          "type": "ByteString",
                          // hex encoded JSON object {"RotateAttributes":["Security Level::Confidential"]}
                          "value": "7B22526F7461746541747472696275746573223A5B225365637572697479204C6576656C3A3A436F6E666964656E7469616C225D7D"
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
          "tag": "ReKeyKeyPairResponse",
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
