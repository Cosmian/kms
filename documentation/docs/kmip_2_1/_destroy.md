#### Specification

This operation is used to indicate to the server that the key material for the specified Managed Object SHALL be
destroyed or rendered inaccessible. The meta-data for the key material SHALL be retained by the server. Objects SHALL
only be destroyed if they are in either Pre-Active or Deactivated state.

#### Implementation

To destroy a key, it must be revoked using the `Revoke` operation first.

Destroyed keys are set in the state `destroyed` on the Cosmian KMS Server. They can only be retrieved using the
`Export` operation. The `Get` operation will return an error. No key material will be returned by the `Export`
operation, only metadata.

#### Example - Symmetric key

Destroying key `f54f14a3-5639-4054-8c23-54af891669db`:

Corresponding `ckms` command:

```shell
  ckms sym keys destroy -k f54f14a3-5639-4054-8c23-54af891669d
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
