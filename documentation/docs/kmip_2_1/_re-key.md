#### Specification

This request is used to generate a replacement key for an existing symmetric key. It is analogous to the Create operation, except that attributes of the replacement key are copied from the existing key, with the exception of the attributes listed in Re-key Attribute Requirements.

As the replacement key takes over the name attribute of the existing key, Re-key SHOULD only be performed once on a given key.

The server SHALL copy the Unique Identifier of the replacement key returned by this operation into the ID Placeholder variable.

For the existing key, the server SHALL create a Link attribute of Link Type Replacement Object pointing to the replacement key. For the replacement key, the server SHALL create a Link attribute of Link Type Replaced Key pointing to the existing key.

An Offset MAY be used to indicate the difference between the Initial Date and the Activation Date of the replacement key. If no Offset is specified, the Activation Date, Process Start Date, Protect Stop Date and Deactivation Date values are copied from the existing key. If Offset is set and dates exist for the existing key, then the dates of the replacement key SHALL be set based on the dates of the existing key as follows.

#### Implementation

The `Re-Key` Operation refreshes Symmetric keys.

### Example - Refresh a Symmetric Key

Corresponding `ckms` CLI command:

```bash
ckms sym keys re-key -k 64c60363-6660-4fd4-9f30-c965a0f72fc3
```

=== "Request"

    ```json
        {
          "tag": "ReKey",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "64c60363-6660-4fd4-9f30-c965a0f72fc3"
            }
          ]
        }

    ```

=== "Response"

    ```json
      {
        "tag": "ReKeyResponse",
        "type": "Structure",
        "value": [
          {
            "tag": "UniqueIdentifier",
            "type": "TextString",
            "value": "64c60363-6660-4fd4-9f30-c965a0f72fc3"
          }
        ]
      }
    ```
