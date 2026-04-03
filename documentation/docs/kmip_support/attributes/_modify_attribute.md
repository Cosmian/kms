### Specification

This operation requests the server to modify an attribute value associated with a Managed Object. The request contains
the Unique Identifier of the Managed Object whose attribute is to be modified, along with the attribute and its new
value. Unlike `SetAttribute`, `ModifyAttribute` is intended to **replace** the value of an existing attribute — it does
not create the attribute if it is absent.

Read-Only attributes SHALL NOT be modified using this operation.

### Implementation

This operation can be applied to all [supported objects](../objects.md).

#### Supported attributes

The following KMIP attributes can be modified:

| Attribute | Notes |
|---|---|
| `ActivationDate` | **Pre-Active objects only.** If the new date ≤ now the object automatically transitions to **Active** (KMIP spec §3.22). |
| `CryptographicAlgorithm` | Replaces the algorithm of the managed object. |
| `CryptographicLength` | Replaces the key length in bits. |
| `CryptographicParameters` | Replaces the cryptographic parameters structure. |
| `CryptographicDomainParameters` | Replaces the domain parameters structure. |
| `CryptographicUsageMask` | Replaces the bitmask of allowed cryptographic usages. |
| `DeactivationDate` | Sets or replaces the deactivation date. |
| `Digest` | Replaces the digest structure. |
| `Link` | Replaces the linked object identifier for the given link type. |
| `Name` | Replaces the first `Name` entry if one exists, otherwise adds it. |
| `ObjectGroup` | Replaces the object group string. |
| `ObjectType` | Replaces the object type. |
| `UniqueIdentifier` | Replaces the unique identifier attribute. |
| `VendorAttribute` | Replaces a vendor attribute value identified by vendor ID + attribute name. |

#### Read-only attributes

The following attributes are **read-only** and SHALL NOT be modified. Any attempt returns an
`Attribute_Read_Only` error:

- `State`
- `CertificateLength`

### Example - Modify the cryptographic length of a symmetric key

Corresponding [KMS CLI](../../../kms_clients/index.md) command:

```bash
  ckms sym keys create my_symmetric_key
  ckms attributes set   -i my_symmetric_key --cryptographic-length 128
  ckms attributes modify -i my_symmetric_key --cryptographic-length 256
```

Output:

```json
Attribute modified successfully
          Unique identifier: my_symmetric_key
```

=== "Request"

    ```json
    {
      "tag": "ModifyAttribute",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "my_symmetric_key"
        },
        {
          "tag": "NewAttribute",
          "type": "Structure",
          "value": [
            {
              "tag": "CryptographicLength",
              "type": "Integer",
              "value": 256
            }
          ]
        }
      ]
    }
    ```

=== "Response"

    ```json
    {
      "tag": "ModifyAttributeResponse",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "my_symmetric_key"
        }
      ]
    }
    ```

### Example - Modify the cryptographic algorithm

```bash
  ckms attributes modify -i my_symmetric_key --cryptographic-algorithm chacha20
```

=== "Request"

    ```json
    {
      "tag": "ModifyAttribute",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "my_symmetric_key"
        },
        {
          "tag": "NewAttribute",
          "type": "Structure",
          "value": [
            {
              "tag": "CryptographicAlgorithm",
              "type": "Enumeration",
              "value": "ChaCha20"
            }
          ]
        }
      ]
    }
    ```

=== "Response"

    ```json
    {
      "tag": "ModifyAttributeResponse",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "my_symmetric_key"
        }
      ]
    }
    ```

### Example - Modify the activation date on a Pre-Active key

`ActivationDate` can only be modified on **Pre-Active** objects. Setting a date that is in the past or equal to the
current time will automatically transition the object to the **Active** state.

```bash
  ckms attributes modify -i my_preactive_key --activation-date 1773571883
```

=== "Request"

    ```json
    {
      "tag": "ModifyAttribute",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "my_preactive_key"
        },
        {
          "tag": "NewAttribute",
          "type": "Structure",
          "value": [
            {
              "tag": "ActivationDate",
              "type": "DateTime",
              "value": "2026-03-15T10:11:23+00:00"
            }
          ]
        }
      ]
    }
    ```

=== "Response"

    ```json
    {
      "tag": "ModifyAttributeResponse",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "my_preactive_key"
        }
      ]
    }
    ```

### Example - Read-only attribute rejection

Attempting to modify a read-only attribute such as `State` will return an `Attribute_Read_Only` error:

=== "Request"

    ```json
    {
      "tag": "ModifyAttribute",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "my_symmetric_key"
        },
        {
          "tag": "NewAttribute",
          "type": "Structure",
          "value": [
            {
              "tag": "State",
              "type": "Enumeration",
              "value": "Active"
            }
          ]
        }
      ]
    }
    ```

=== "Response"

    ```json
    {
      "tag": "ResponseMessage",
      "type": "Structure",
      "value": [
        {
          "tag": "ResponseHeader",
          "type": "Structure",
          "value": [
            {
              "tag": "ProtocolVersion",
              "type": "Structure",
              "value": [
                { "tag": "ProtocolVersionMajor", "type": "Integer", "value": 2 },
                { "tag": "ProtocolVersionMinor", "type": "Integer", "value": 1 }
              ]
            },
            { "tag": "TimeStamp", "type": "DateTime", "value": "2026-03-15T10:11:23+00:00" },
            { "tag": "BatchCount", "type": "Integer", "value": 1 }
          ]
        },
        {
          "tag": "BatchItem",
          "type": "Structure",
          "value": [
            { "tag": "Operation", "type": "Enumeration", "value": "ModifyAttribute" },
            { "tag": "ResultStatus", "type": "Enumeration", "value": "OperationFailed" },
            { "tag": "ResultReason", "type": "Enumeration", "value": "Attribute_Read_Only" },
            { "tag": "ResultMessage", "type": "TextString", "value": "DENIED" }
          ]
        }
      ]
    }
    ```
