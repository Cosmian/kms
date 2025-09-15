#### Specification

This operation is used to indicate to the server that the key material for the specified Managed Object SHALL be
destroyed or rendered inaccessible. The meta-data for the key material SHALL be retained by the server. Objects SHALL
only be destroyed if they are in either Pre-Active or Deactivated state.

#### Implementation

To destroy a key, it must be revoked using the `Revoke` operation first, unless it belongs to an external store,
such as an HSM.

Cosmian has added an option `Remove` flag to the `Destroy` operation. If the `Remove` flag is set to `true`, the key
is completely removed from the database. This does not follow the KMIP 2.1 specification, but is useful in scenarios
where the key was incorrectly created and the ID must ne re-used or for GDPR compliance, when the key is associated
with personal data.

HSM keys are systematically removed when calling the destroy operation.

Unless, they are removed, destroyed keys are set in the state `destroyed` on the Cosmian KMS Server. They can only be
retrieved using the`Export` operation. The `Get` operation will return an error. No key material will be returned by the
`Export` operation, only metadata.

#### Example - Symmetric key

Destroying key `f54f14a3-5639-4054-8c23-54af891669db`:

Corresponding `cosmian` command:

```shell
  cosmian kms sym keys destroy -k f54f14a3-5639-4054-8c23-54af891669db --remove
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
