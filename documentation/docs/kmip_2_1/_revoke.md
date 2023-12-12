#### Specification

This operation requests the server to revoke a Managed Cryptographic Object or an Opaque Object.

The request contains a reason for the revocation (e.g., "key compromise", "cessation of operation", etc.).

The operation has one of two effects. If the revocation reason is "key compromise" or "CA compromise", then the object
is placed into the "compromised" state; the Date is set to the current date and time; and the Compromise Occurrence Date
is set to the value (if provided) in the Revoke request and if a value is not provided in the Revoke request then
Compromise Occurrence Date SHOULD be set to the Initial Date for the object. If the revocation reason is neither "key
compromise" nor "CA compromise", the object is placed into the "deactivated" state, and the Deactivation Date is set to
the current date and time.

#### Implementation

The state of the object is kept as specified but the revocation reason is currently not maintained.
Once an Object is revoked, it can only be retrieved using the `Export` operation. The `Get` operation will return an
error.

A `Revoked` object can be destroyed using the `Destroy` operation.

#### Example - Symmetric key

Revoking key `f54f14a3-5639-4054-8c23-54af891669db` with reason `key was compromised`.

Corresponding `ckms` CLI command:

```bash
  ckms sym keys revoke -k f54f14a3-5639-4054-8c23-54af891669db "key was compromised"
```

=== "Request"

    ```json
        {
          "tag": "Revoke",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "f54f14a3-5639-4054-8c23-54af891669db"
            },
            {
              "tag": "RevocationReason",
              "type": "TextString",
              "value": "key was compromised"
            }
          ]
        }

    ```

=== "Response"

    ```json
        {
          "tag": "RevokeResponse",
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
