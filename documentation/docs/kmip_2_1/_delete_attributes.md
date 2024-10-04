### Specification

This operation requests the server to delete an attribute associated with a Managed Object. The request contains the Unique Identifier of the Managed Object whose attribute is to be deleted, the Current Attribute of the attribute. Attributes that are always REQUIRED to have a value SHALL never be deleted by this operation. Attempting to delete a non-existent attribute or specifying an Current Attribute for which there exists no attribute value SHALL result in an error. If no Current Attribute is specified in the request, and an Attribute Reference is specified, then all instances of the specified attribute SHALL be deleted.

### Implementation

This operation can be applied to all [supported objects](./objects.md). One or more attributes can be set at once.

### Example - Delete links on Certificate

Delete the links on a certificate object.

Corresponding `ckms` CLI command:

```bash
  ckms delete-attributes -i 03948573-9348-aaaa-aaaa-93857383 --public-key-id xxxxxxxx-yyyy-yyyy-yyyy-zzzzzzzzzzzz --private-key-id xxxxxxxx-yyyy-yyyy-yyyy-zzzzzzzzzzzz --certificate-id xxxxxxxx-yyyy-yyyy-yyyy-zzzzzzzzzzzz
```

The request deletes the KMIP links of the public key and the private key of the underlying certificate.
The `DeleteAttribute` operation being unitary, 3 requests are sent to the server, one for each link.

Output is:

```json
Attribute deleted successfully
          Unique identifier: 6209aa2a-900f-4a1c-b2ca-9b4af1bbd1d1
[
  {
    "LinkType": "PublicKeyLink",
    "LinkedObjectIdentifier": "xxxxxxxx-yyyy-yyyy-yyyy-zzzzzzzzzzzz"
  }
]
Attribute deleted successfully
          Unique identifier: 6209aa2a-900f-4a1c-b2ca-9b4af1bbd1d1
[
  {
    "LinkType": "PrivateKeyLink",
    "LinkedObjectIdentifier": "xxxxxxxx-yyyy-yyyy-yyyy-zzzzzzzzzzzz"
  }
]
Attribute deleted successfully
          Unique identifier: 6209aa2a-900f-4a1c-b2ca-9b4af1bbd1d1
[
  {
    "LinkType": "CertificateLink",
    "LinkedObjectIdentifier": "xxxxxxxx-yyyy-yyyy-yyyy-zzzzzzzzzzzz"
  }
]
```

=== "First Request"

    ```json
        {
          "tag": "DeleteAttribute",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "10a875bd-9cc5-45a3-99ef-b2cdedd848bf"
            },
            {
              "tag": "CurrentAttribute",
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
          "tag": "DeleteAttribute",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "10a875bd-9cc5-45a3-99ef-b2cdedd848bf"
            },
            {
              "tag": "CurrentAttribute",
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

=== "Third Request"

    ```json
        {
          "tag": "DeleteAttribute",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "10a875bd-9cc5-45a3-99ef-b2cdedd848bf"
            },
            {
              "tag": "CurrentAttribute",
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
          "tag": "DeleteAttributeResponse",
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
