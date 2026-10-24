# Delete

## Specification

This operation requests the server to delete an attribute associated with a Managed Object. The request contains the Unique Identifier of the Managed Object whose attribute is to be deleted, the Current Attribute of the attribute. Attributes that are always REQUIRED to have a value SHALL never be deleted by this operation. Attempting to delete a non-existent attribute or specifying an Current Attribute for which there exists no attribute value SHALL result in an error. If no Current Attribute is specified in the request, and an Attribute Reference is specified, then all instances of the specified attribute SHALL be deleted.

## Implementation

This operation can be applied to all [supported objects](../objects.md). One or more attributes can be set at once.

### Read-only attributes

The following attributes are **read-only** for `DeleteAttribute`. Any attempt returns an `Attribute_Read_Only` error
before the object is touched:

- `UniqueIdentifier`, `ObjectType`, `CryptographicLength`, `CertificateLength`, `Digest`
- `InitialDate`, `LastChangeDate`, `OriginalCreationDate`, `Fresh`
- `State`, `CryptographicAlgorithm`, `KeyFormatType`, `ArchiveDate`, `CompromiseDate`, `DestroyDate`, `CertificateType`
- `KeyValuePresent`, `OpaqueDataType`, `X509CertificateIdentifier`, `X509CertificateIssuer`, `X509CertificateSubject`
- `Sensitive`, `Extractable`, `AlwaysSensitive`, `NeverExtractable`
- `CryptographicUsageMask`, `DigitalSignatureAlgorithm`, `ActivationDate`, `DeactivationDate`
- `RotateAutomatic`, `RotateGeneration`, `RotateDate`, `RotateLatest`
- server-owned KMIP 1.x vendor attributes (names starting with `y-`)

### Other rules

- A Current Attribute that matches no instance returns `Attribute_Instance_Not_Found` if the attribute exists, else `Attribute_Not_Found`.
- A request that deletes nothing returns `Attribute_Not_Found`.
- A reference to `Link` clears every link. A `Link` with an empty linked identifier removes every link of that type.
- `UsageLimits`, `Link`, `LinkType`, `RotateInterval` and `RevocationReason` can be deleted only by the object owner or by a user holding an explicit `DeleteAttribute` grant (`Permission_Denied` otherwise).
- Every successful Delete updates the `LastChangeDate`.
- KMIP 1.4 responses echo the deleted attribute.

## Example - Delete links on Certificate

First, for the demo purpose create a certificate:

```bash
  ckms certificates certify --generate-key-pair --subject-name C=yo --algorithm rsa2048 -c my_certificate
```

Delete the links on a certificate object.

Corresponding [KMS CLI](../../kms_clients/index.md) command:

```bash
  ckms attributes delete -i my_certificate --public-key-id xxxxxxxx-yyyy-yyyy-yyyy-zzzzzzzzzzzz --private-key-id xxxxxxxx-yyyy-yyyy-yyyy-zzzzzzzzzzzz --certificate-id xxxxxxxx-yyyy-yyyy-yyyy-zzzzzzzzzzzz
```

The request deletes the KMIP links of the public key and the private key of the underlying certificate.
The `DeleteAttribute` operation being unitary, 3 requests are sent to the server, one for each link.

Output is:

```json
Attribute deleted successfully
          Unique identifier: my_certificate
[
  {
    "LinkType": "PublicKeyLink",
    "LinkedObjectIdentifier": "xxxxxxxx-yyyy-yyyy-yyyy-zzzzzzzzzzzz"
  }
]
Attribute deleted successfully
          Unique identifier: my_certificate
[
  {
    "LinkType": "PrivateKeyLink",
    "LinkedObjectIdentifier": "xxxxxxxx-yyyy-yyyy-yyyy-zzzzzzzzzzzz"
  }
]
Attribute deleted successfully
          Unique identifier: my_certificate
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
          "value": "my_certificate"
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
          "value": "my_certificate"
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
          "value": "my_certificate"
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
          "value": "my_certificate"
        }
      ]
    }
    ```
