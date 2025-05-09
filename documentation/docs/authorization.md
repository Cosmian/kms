The authorization system in the Cosmian Key Management Service (KMS) operates based on two fundamental principles:

1. **Ownership:** Every cryptographic object has an assigned owner. The ownership is established when an object is
   created using any of the following KMIP operations: `Create`, `CreateKeyPair`, or `Import`. As an owner, a user holds
   the privilege to carry out all supported KMIP operations on their objects.

2. **Access rights delegation:** owners can grant access rights, allowing one or more users to perform certain KMIP
   operations on an object. When granted such rights, a user can invoke the corresponding KMIP operation on the KMS for
   that particular object. The owner retains the authority to withdraw these access rights at any given time.

## Privileged users

By default, all users are allowed to create or import objects in the KMS.

However, when the KMS server is configured with a list of privileged users, object creation rights are restricted as follows:

- Privileged users can create or import objects and are authorized to grant or revoke object creation permissions for other users.
- Regular users cannot create or import objects unless they have explicitly been granted permission by a privileged user.
- Regular users cannot grant or revoke creation permissions for others.
- Privileged users cannot revoke object creation permissions from other privileged users.

!!!important  "The Wildcard User: *"
      In addition to regular users, a special user called `*` (the wildcard user) can be used to grant access rights on
      objects to all users.
