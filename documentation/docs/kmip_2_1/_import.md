### Specification

This operation requests the server to Import a Managed Object specified by its Unique Identifier.
The request specifies the object being imported and all the attributes to be assigned to the object.

The attribute rules for each attribute for "Initially set by" and "When implicitly set" SHALL NOT be enforced as all attributes MUST be set to the supplied values rather than any server-generated values.

The response contains the Unique Identifier provided in the request or assigned by the server. The server SHALL copy the Unique Identifier returned by this operation into the ID Placeholder variable.

### Implementation

The server fully implements import operations for the supported objects in PlainText mode but only for Symmetric Keys in Wrapped mode.

