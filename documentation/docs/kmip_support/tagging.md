# Objects Tagging

The Eviden KMS server supports the tagging of objects. Tags are arbitrary strings that can be attached to objects.
Tags can be used to group objects together, and to find objects for most operations, such as export, import, encrypt, decrypt, etc.

In addition, the KMS server will automatically add a system tag to objects based on the object type:

- `_sk`: for a private key
- `_pk`: for a public key
- `_kk`: for a symmetric key
- `_uk`: for a Covercrypt user decryption key
- `_cert`: for a X509 certificate
- `_sd`: for a secret data
- `_oo`: for an opaque object
- `_pgp`: for an OpenPGP key

Since there is no provision in the KMIP 2.1 specification for tagging. The Eviden KMS server implements tagging using the following KMIP 2.1 extensions:

1. When `Attributes` are passed as part of the KMIP operation, such as in the `Create`, `Create Key Pair`, `Locate`, `Certify` and `Import` operations,
the tags are passed as `VendorAttributes` with the server's configured vendor identification (default: `cosmian`, configurable via `--vendor-identification` / `KMS_VENDOR_IDENTIFICATION`) and attribute name `tag`.
The value is the serialization of the tags as a JSON array of strings.

2. When unique identifiers are passed as part of the KMIP operation, such as in the `Certify`, `Encrypt`, `Export`, `Decrypt`, `Get`, `Get Attributes`, `Revoke`, and `Destroy` operations,
the tags are in the unique identifier itself as a serialized JSON array e.g. `[ "tag1", "tag2" ]`.

## Example

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

## Certificate serial number tag: `_serial=<HEX>`

In addition to `_cert`, every X.509 certificate carries a system tag `_serial=<SERIAL_IN_UPPERCASE_HEX>`,
computed by the server from the certificate DER (the format of `openssl x509 -noout -serial`), for example `_serial=0A1B2C3D`.
It lets you locate a certificate by its serial number without any KMIP knowledge:

```bash
ckms locate --tag _serial=0A1B2C3D
```

- **When it is set**: on `Certify`, `ReCertify`, `Import` and `Register` of a certificate, including the leaf and chain certificates of a PKCS#12 import.
- **Client values never win**: a `_serial=` tag supplied on `Import`, `Register` or PKCS#12 import is dropped, and one supplied on `Certify` is rejected (user tags cannot start with `_`); the tag inherited by a renewed certificate (`ReCertify`) is replaced by the value computed from the new certificate.
- **Not unique**: a serial number is unique only per issuer. The same tag can match certificates issued by different CAs; combine it with other tags or attributes to narrow the result.
- **Unrelated to enrollment**: this tag is distinct from the internal `_enrolled_serial:<CA_UID>:<HEX>` tag used by certificate enrollment.

### Certificates created before this tag existed

On the first start after an upgrade, the server tags the existing certificates (those carrying `_cert`) once, on every database backend
(SQLite, PostgreSQL, MySQL/MariaDB and Redis-Findex). Existing tags are kept. Completion is recorded by the
`certificate_serial_tag_backfilled` marker (a row of the [`parameters` table](../configuration/database/tables.md) on the SQL backends,
a key on Redis-Findex), so the scan runs only once; an interrupted run is retried at the next start.

A certificate whose DER cannot be parsed is skipped and stays without a `_serial=` tag. On every backend a warning
is logged when the stored object cannot be deserialized (see the [log reference](../configuration/log-reference.md)).

The backfill runs once, at the first start of an upgraded server. During a rolling upgrade, upgrade every node before the first upgraded node starts; a certificate created by a not-yet-upgraded node after the marker is written stays untagged.
