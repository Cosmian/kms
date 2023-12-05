#### specification

This operation requests the server to revoke a Managed Cryptographic Object or an Opaque Object.

The request contains a reason for the revocation (e.g., "key compromise", "cessation of operation", etc.).

The operation has one of two effects. If the revocation reason is "key compromise" or "CA compromise", then the object is placed into the "compromised" state; the Date is set to the current date and time; and the Compromise Occurrence Date is set to the value (if provided) in the Revoke request and if a value is not provided in the Revoke request then Compromise Occurrence Date SHOULD be set to the Initial Date for the object. If the revocation reason is neither "key compromise" nor "CA compromise", the object is placed into the "deactivated" state, and the Deactivation Date is set to the current date and time.

#### implementation

The state of the object is kept as specified bu the revocation reason is currently not maintained.

=== "Java"

    ``` java
    String keyUniqueIdentifier = ...;
    abe.revokeKey(keyUniqueIdentifier);
    ```