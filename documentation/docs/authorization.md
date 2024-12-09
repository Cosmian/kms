The authorization system in the Cosmian Key Management Service (KMS) operates based on two fundamental principles:

1. **Ownership:** Every cryptographic object has an assigned owner. The ownership is established when an object is
   created using any of the following KMIP operations: `Create`, `CreateKeyPair`, or `Import`. As an owner, a user holds
   the privilege to carry out all supported KMIP operations on their objects.

2. **Access rights delegation:** owners can grant access rights, allowing one or more users to perform certain KMIP
   operations on an object. When granted such rights, a user can invoke the corresponding KMIP operation on the KMS for
   that particular object. The owner retains the authority to withdraw these access rights at any given time.

!!!important  "The Wildcard User: *"
      In addition to regular users, a special user called `*` (the wildcard user) can be used to grant access rights on
      objects to all users.

To manage access rights, the user can call the following endpoints or use the [Cosmian CLI](../cosmian_cli/index.md).
