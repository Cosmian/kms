The Cosmian KMS server supports the tagging of objects. Tags are arbitrary strings that can be attached to objects.
Tags can be used to group objects together, and to find objects for most operations, such as export, import, encrypt, decrypt, etc.

In addition, the KMS server will automatically add a system tag to objects based on the object type:

- `_sk`: for a private key
- `_pk`: for a public key
- `_kk`: for a symmetric key
- `_uk`: for a Covercrypt user decryption key
- `_cert`: for a X509 certificate

Since there is no provision in the KMIP 2.1 specification for tagging. The Cosmian KMS server implements tagging using the following KMIP 2.1 extensions:

1. When `Attributes` are passed as part of the KMIP operation, such as in the `Create`, `Create Key Pair`, `Locate`, `Certify` and `Import` operations,
the tags are passed as `VendorAttributes` with the vendor identification `Cosmian` and attribute name `tag`.
The value is the serialization of the tags as a JSON array of strings.

2. When unique identifiers are passed as part of the KMIP operation, such as in the `Certify`, `Encrypt`, `Export`, `Decrypt`, `Get`, `Get Attributes`, `Revoke`, and `Destroy` operations,
the tags are in the unique identifier itself as a serialized JSON array e.g. `[ "tag1", "tag2" ]`.

**Example**

Export the Symmetric key (tag `_kk`) with user tag `myTag`:

```json
{
  "tag": "Export",
  "type": "Structure",
  "value": [
    {
      "tag": "UniqueIdentifier",
      "type": "TextString",
      "value": "[\"_kk\",\"myTag\"]"
    },
    {
      "tag": "KeyFormatType",
      "type": "Enumeration",
      "value": "AsRegistered"
    }
  ]
}
```
