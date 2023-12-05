#### specification

This request is used to generate a replacement key pair for an existing public/private key pair. It is analogous to the Create Key Pair operation, except that attributes of the replacement key pair are copied from the existing key pair, with the exception of the attributes listed in Re-key Key Pair Attribute Requirements tor.

As the replacement of the key pair takes over the name attribute for the existing public/private key pair, Re-key Key Pair SHOULD only be performed once on a given key pair.

For both the existing public key and private key, the server SHALL create a Link attribute of Link Type Replacement Key pointing to the replacement public and private key, respectively. For both the replacement public and private key, the server SHALL create a Link attribute of Link Type Replaced Key pointing to the existing public and private key, respectively.

The server SHALL copy the Private Key Unique Identifier of the replacement private key returned by this operation into the ID Placeholder variable.

An Offset MAY be used to indicate the difference between the Initial Date and the Activation Date of the replacement key pair. If no Offset is specified, the Activation Date and Deactivation Date values are copied from the existing key pair. If Offset is set and dates exist for the existing key pair, then the dates of the replacement key pair SHALL be set based on the dates of the existing key pair as follows

#### implementation

The Re-Key Key Pair Operation is the main mechanism to rotate ABE attributes on the Cosmian KMS Server. By updating, through this operation, the Policy held by a Master Private Key in it Vendor Attributes, the Cosmian KMS Server will automatically

- update the Policy held by the Master Public Key
- and re-key all non revoked User Decryption Keys holding the rotated policy attributes in a way that they will now be able to decrypt cipher texts encrypted with attributes before and after the rotation.

The operation has currently no other usages on the Cosmian server.

=== "Java"

    ``` java
    String privateMasterKeyUniqueIdentifier = ...;
    // This will rekey in the KMS:
    //
    // - the Master Public Key
    // - all User Decryption Keys that contain one of these attributes in their
    // policy and are not revoked.
    //
    // the ABE policy attributes to rotate
    Attr[] abePolicyAttributes = ...;
    abe.revokeAttributes(privateMasterKeyUniqueIdentifier, Attr[] abePolicyAttributes);
    ```
