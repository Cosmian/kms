# Re-Key Key Pair

## Specification

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

## Implementation

The `Re-Key Key Pair` Operation rotates RSA, EC and PQC key pairs: the new private key gets a new Unique Identifier and
the new public key gets `<private key uid>_pk`. It also rotates Covercrypt master keys in place.

- The existing private key must be Active, Deactivated or Compromised; any other state returns `Permission_Denied`.
- The caller also needs the `Rekey` permission on the public key named by the private key's Public Key Link;
  otherwise the request fails with `Object_Not_Found`.
- Request attributes that change the cryptographic algorithm, length or curve return `Invalid_Field`.
- `Offset` is an Interval in seconds: the new keys' Activation Date is `now + Offset`, and their Process Start, Protect
  Stop and Deactivation Dates are shifted by the same amount. Without it these dates are copied.
- The request Common, Private and Public Key `Attributes` are applied to the new keys, except the attributes the server
  manages (identity, links, names, lifecycle dates, state, rotation metadata).
- Active existing keys become Deactivated (Deactivation Date = now); keys in another state keep their state.

For Covercrypt, by updating, through this operation, the Policy held by a master secret key in its Vendor Attributes,
the Eviden KMS Server will automatically

- update the Policy held by the Master Public Key
- and re-key all non revoked User Decryption Keys holding the rotated policy attributes in a way that they will now be
  able to decrypt cipher texts encrypted with attributes before and after the rotation.

## Example - Rotate the `Security Level::Confidential` attribute

Corresponding [KMS CLI](../../kms_clients/index.md) command:

```bash
ckms cc keys rekey -k b652a48a-a48c-4dc1-bd7e-cf0e5126b7b9 "Security Level::Confidential"
```

Using a JSON TTLV request to rotate the `Security Level::Confidential` attribute on a master secret key, construct a JSON object containing
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
