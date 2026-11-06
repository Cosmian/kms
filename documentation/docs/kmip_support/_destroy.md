# Destroy

## Specification

This operation is used to indicate to the server that the key material for the specified Managed Object SHALL be
destroyed or rendered inaccessible. The meta-data for the key material SHALL be retained by the server. Objects SHALL
only be destroyed if they are in either Pre-Active or Deactivated state.

## Implementation

Permission is checked first: objects the caller may not destroy are skipped, and if none is left the server returns
`Object_Not_Found`.

- An `Active` object returns `Wrong_Key_Lifecycle_State`: revoke it first.
- An already `Destroyed` object returns `Object_Destroyed`, even with the `Remove` flag.
- `Pre-Active` and `Deactivated` objects become `Destroyed`; `Compromised` objects become `Destroyed Compromised`.
- The Destroy Date is set.

Eviden has added an option `Remove` flag to the `Destroy` operation. If the `Remove` flag is set to `true`, the key
is completely removed from the database. This does not follow the KMIP 2.1 specification, but is useful in scenarios
where the key was incorrectly created and the ID must ne re-used or for GDPR compliance, when the key is associated
with personal data.

HSM keys can only be deleted by the HSM administrator.

Unless they are removed, destroyed objects can only be retrieved using the `Export` operation, which returns no key
material. The `Get` operation returns `Object_Destroyed`.

## Example - Symmetric key

Destroying key `f54f14a3-5639-4054-8c23-54af891669db`:

Corresponding `cosmian` command:

```shell
  ckms sym keys destroy -k f54f14a3-5639-4054-8c23-54af891669db --remove
```

=== "Request"

    ```json
    {
      "tag": "Destroy",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "f54f14a3-5639-4054-8c23-54af891669db"
        },
        {
          "tag": "Remove",
          "type": "Boolean",
          "value": true
        }
      ]
    }
    ```

=== "Response"

    ```json
    {
      "tag": "DestroyResponse",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "f54f14a3-5639-4054-8c23-54af891669db"
        }
      ]
    }
    ```
