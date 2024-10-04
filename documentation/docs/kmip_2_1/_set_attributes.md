### Specification

This operation requests the server to either add or modify an attribute. The request contains the Unique Identifier of the Managed Object to which the attribute pertains, along with the attribute and value. If the object did not have any instances of the attribute, one is created. If the object had exactly one instance, then it is modified. If it has more than one instance an error is raised. Read-Only attributes SHALL NOT be added or modified using this operation.

### Implementation

This operation can be applied to all [supported objects](./objects.md). One or more attributes can be set at once. The operation is idempotent, meaning that if the attribute is already set, the operation will not fail.

### Example - A symmetric key

Set an attribute of a symmetric key by its unique identifier `027cced1-ff2b-4bd3-a200-db1041583bdc`.

Corresponding `ckms` CLI command:

```bash
  ckms set-attributes -i 6209aa2a-900f-4a1c-b2ca-9b4af1bbd1d1 --activation-date 1726211157791
```

The request sets the activation date of a symmetric key.

The response contains all the system and user tags associated with the key. This is the hex encoded value of a JSON
array with value

```json
Attribute set successfully
          Unique identifier: 6209aa2a-900f-4a1c-b2ca-9b4af1bbd1d1
```

=== "Request"

    ```json
        {
          "tag": "SetAttribute",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "10a875bd-9cc5-45a3-99ef-b2cdedd848bf"
            },
            {
              "tag": "NewAttribute",
              "type": "Structure",
              "value": [
                {
                  "tag": "Link",
                  "type": "Structure",
                  "value": [
                    {
                      "tag": "LinkType",
                      "type": "Enumeration",
                      "value": "CertificateLink"
                    },
                    {
                      "tag": "LinkedObjectIdentifier",
                      "type": "TextString",
                      "value": "certificate_id"
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
          "tag": "SetAttributeResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "6209aa2a-900f-4a1c-b2ca-9b4af1bbd1d1"
            }
          ]
        }
```

### Example - Set links on Certificate

Set the links on a certificate object. It will set 2 KMIP attributes.

Corresponding `ckms` CLI command:

```bash
  ckms set-attributes -i 03948573-9348-aaaa-aaaa-93857383 --public-key-id xxxxxxxx-yyyy-yyyy-yyyy-zzzzzzzzzzzz --private-key-id xxxxxxxx-yyyy-yyyy-yyyy-zzzzzzzzzzzz
```

The request set the KMIP links of the public key and the private key of the underlying certificate.
The `SetAttribute` operation being unitary, 2 requests are sent to the server, one for each link.

Output is:

```json
Attribute set successfully
          Unique identifier: 6209aa2a-900f-4a1c-b2ca-9b4af1bbd1d1
[
  {
    "LinkType": "PublicKeyLink",
    "LinkedObjectIdentifier": "xxxxxxxx-yyyy-yyyy-yyyy-zzzzzzzzzzzz"
  }
]
Attribute set successfully
          Unique identifier: 6209aa2a-900f-4a1c-b2ca-9b4af1bbd1d1
[
  {
    "LinkType": "PrivateKeyLink",
    "LinkedObjectIdentifier": "xxxxxxxx-yyyy-yyyy-yyyy-zzzzzzzzzzzz"
  }
]
```

=== "First Request"

    ```json
        {
          "tag": "SetAttribute",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "10a875bd-9cc5-45a3-99ef-b2cdedd848bf"
            },
            {
              "tag": "NewAttribute",
              "type": "Structure",
              "value": [
                {
                  "tag": "Link",
                  "type": "Structure",
                  "value": [
                    {
                      "tag": "LinkType",
                      "type": "Enumeration",
                      "value": "PublicKeyLink"
                    },
                    {
                      "tag": "LinkedObjectIdentifier",
                      "type": "TextString",
                      "value": "xxxxxxxx-yyyy-yyyy-yyyy-zzzzzzzzzzzz"
                    }
                  ]
                }
              ]
            }
          ]
        }
    ```

=== "Second Request"

    ```json
        {
          "tag": "SetAttribute",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "10a875bd-9cc5-45a3-99ef-b2cdedd848bf"
            },
            {
              "tag": "NewAttribute",
              "type": "Structure",
              "value": [
                {
                  "tag": "Link",
                  "type": "Structure",
                  "value": [
                    {
                      "tag": "LinkType",
                      "type": "Enumeration",
                      "value": "PrivateKeyLink"
                    },
                    {
                      "tag": "LinkedObjectIdentifier",
                      "type": "TextString",
                      "value": "xxxxxxxx-yyyy-yyyy-yyyy-zzzzzzzzzzzz"
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
          "tag": "SetAttributeResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "6209aa2a-900f-4a1c-b2ca-9b4af1bbd1d1"
            }
          ]
        }
```
