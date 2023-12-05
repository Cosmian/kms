#### specification

This operation requests that the server returns a Managed Object specified by its Unique Identifier, together with its
attributes.

The Key Format Type, Key Wrap Type, Key Compression Type and Key Wrapping Specification SHALL have the same semantics as
for the Get operation. If the Managed Object has been Destroyed then the key material for the specified managed object
SHALL not be returned in the response.

The server SHALL copy the Unique Identifier returned by this operations into the ID Placeholder variable.

#### implementation

The Export operation allows exporting objects which have been revoked or destroyed.
When an object is destroyed, the key material cannot be exported anymore; only the attributes are returned.

To be able to export an Object the user must have the `export` permission on the object or be the object owner.

