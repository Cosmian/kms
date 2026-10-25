# Set

## Specification

This operation requests the server to either add or modify an attribute. The request contains the Unique Identifier of the Managed Object to which the attribute pertains, along with the attribute and value. If the object did not have any instances of the attribute, one is created. If the object had exactly one instance, then it is modified. If it has more than one instance an error is raised. Read-Only attributes SHALL NOT be added or modified using this operation.

## Implementation

This operation can be applied to all [supported objects](../objects.md). One or more attributes can be set at once. The operation is idempotent, meaning that if the attribute is already set, the operation will not fail.

### Read-only attributes

The following attributes are **read-only** for `SetAttribute` (KMIP 2.1 §6.1.51). Any attempt returns a
`Read_Only_Attribute` error before the object is touched; the message begins with
`DENIED: this attribute is server-managed`:

- `UniqueIdentifier`, `ObjectType`, `ShortUniqueIdentifier`, `KeyFormatType`, `KeyValuePresent`, `OpaqueDataType`
- `CryptographicAlgorithm`, `CryptographicDomainParameters`, `CryptographicLength`, `DigitalSignatureAlgorithm`,
  `NISTKeyType`, `Digest`, `RandomNumberGenerator`, `ProtectionStorageMasks`
- `CertificateType`, `CertificateLength`, `CertificateAttributes`, `X509CertificateIdentifier`,
  `X509CertificateSubject`, `X509CertificateIssuer`
- `InitialDate`, `LastChangeDate`, `OriginalCreationDate`, `ArchiveDate`, `DestroyDate`, `CompromiseDate`,
  `CompromiseOccurrenceDate`, `Fresh`
- `State` (use Revoke and Destroy to change it)
- `AlwaysSensitive`, `NeverExtractable`
- `RotateGeneration`, `RotateDate`, `RotateLatest`

`AddAttribute` refuses the same attributes, plus `RotateAutomatic`, with the same `Read_Only_Attribute` error.

### Attributes requiring a grant

`Sensitive`, `Extractable`, `UsageLimits`, `CryptographicUsageMask`, `ActivationDate`, `DeactivationDate`, `Link`,
`LinkType`, `RotateInterval` and `RevocationReason` can be set only by the object owner or by a user holding an
explicit `SetAttribute` grant. A `Get` grant is not enough: the refusal is `Permission_Denied`.

### Other rules

- `ActivationDate` can be set only on a Pre-Active object, else `Wrong_Key_Lifecycle_State` (`Permission_Denied` for KMIP 2.0 clients).
- Set `Name` replaces the single instance; with more than one instance it returns `Multi_Valued_Attribute`.
- Every successful Set updates the `LastChangeDate`.

## Example - A symmetric key

Set an attribute of a symmetric key by its unique identifier `027cced1-ff2b-4bd3-a200-db1041583bdc`.

First, create a symmetric key with the [KMS CLI](../../kms_clients/index.md):

```bash
  ckms sym keys create my_symmetric_key
```

The request below sets a link on that key.

=== "Request"

    ```json
    {
      "tag": "SetAttribute",
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
          "value": "my_symmetric_key"
        }
      ]
    }
    ```

## Example - Set links on Certificate

Set the links on a certificate object. It will set 2 KMIP attributes.

Corresponding [KMS CLI](../../kms_clients/index.md) command:

```bash
  ckms attributes set -i 03948573-9348-aaaa-aaaa-93857383 --public-key-id xxxxxxxx-yyyy-yyyy-yyyy-zzzzzzzzzzzz --private-key-id xxxxxxxx-yyyy-yyyy-yyyy-zzzzzzzzzzzz
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
          "value": "my_symmetric_key"
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
          "value": "my_symmetric_key"
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
          "value": "my_symmetric_key"
        }
      ]
    }
    ```
