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

To manage access rights, the user can call the following endpoints or use
the `ckms` [command line interface](./cli/cli.md).

### Granting an access right

An owner of an object grants an access right to a specific user for a given operation on a given object.
The supported KMIP operations are: `get`, `export`, `encrypt`, `decrypt`, `import`, `revoke`, `destroy`.

=== "ckms"

      ```
      ➜ ckms access grant --help
      Grant another user an access right to an object.

      This command can only be called by the owner of the object.

      The right is granted for one of the supported KMIP operations: create, get, encrypt, decrypt, import, revoke, locate, rekey, destroy

      Usage: ckms access grant <USER> <OBJECT_UID> <OPERATION>

      Arguments:
      <USER>
               The user identifier to allow

      <OBJECT_UID>
               The object unique identifier stored in the KMS

      <OPERATION>
               The KMIP operation to allow

      Options:
      -h, --help
               Print help (see a summary with '-h')
      ```

=== "REST"

      `POST` to the `/access/grant` endpoint with the JSON object:

      ```json
      {
         "unique_identifier": "1ae2...25df",  // the object unique identifier
         "user_id": "john.doe@acem.com", // the user identifier to allow
         "operation_type": "get" // the KMIP operation to allow
      }
      ```

      The response is a JSON object:

      ```json
      {
      "success": "a success message"
      }
      ```

### Revoking an access right

An owner of an object can revoke an access right to a specific user for a given operation on a given object at any time.

=== "ckms"

      ```
      ➜ ckms access revoke --help
      Revoke another user access right to an object.

      This command can only be called by the owner of the object.

      Usage: ckms access revoke <USER> <OBJECT_UID> <OPERATION>

      Arguments:
      <USER>
               The user to revoke access to

      <OBJECT_UID>
               The object unique identifier stored in the KMS

      <OPERATION>
               The operation to revoke (create, get, encrypt, decrypt, import, revoke, locate, rekey, destroy)

      Options:
      -h, --help
               Print help (see a summary with '-h')
      ```

=== "REST"

      `POST` to the `/access/revoke` endpoint with the JSON object:

      ```json
      {
         "unique_identifier": "1ae2...25df",  // the object unique identifier
         "user_id": "john.doe@acem.com", // the user identifier to allow
         "operation_type": "get" // the KMIP operation to allow
      }
      ```

      The response is a JSON object:

      ```json
      {
      "success": "a success message"
      }
      ```

### Listing an object access rights

The owner of an object can list all the access rights that have been granted to another object.

=== "ckms"

      ```
      ➜ ckms access list --help
      List the access rights granted on an object to other users.

      This command can only be called by the owner of the object. Returns a list of users and the operations they have been granted access to.

      Usage: ckms access list <OBJECT_UID>

      Arguments:
      <OBJECT_UID>
               The object unique identifier

      Options:
      -h, --help
               Print help (see a summary with '-h')
      ```

=== "REST"

      `GET` to the `/access/list/{object_unique_id}` endpoint:

      The response is a JSON array:

      ```json
      [
         {
            "user_id": "the user identifier the access rights are granted to",
            "operations": [ <operation type> ]
         }
      ]
      ```

      where `<operation type>` is one of the following: `export`, `get`, `encrypt`, `decrypt`, `import`, `revoke`,  `destroy`.

### Listing the objects owned by a user

A user can list all the objects it owns (i.e. the objects it created using either the `Create`, `CreateKeyPair`,
or `Import` KMIP operations).

=== "ckms"

      ```
      ➜ ckms access owned --help
      List the objects owned by the calling user.

      Owners of objects can perform any operation on these objects and can grant access rights on any of these operations to any other user.

      Usage: ckms access owned

      Options:
      -h, --help
               Print help (see a summary with '-h')
      ```

=== "REST"

      `GET` to the `/access/owned` endpoint:

      The response is a JSON array:

      ```json
      [
         {
            "object_id": "the object unique identifier",
            "state": "<state>",
            "attributes": "<attributes>",
         }
      ]
      ```

      where:

      - `<state>` is one of the following KMIP states: `PreActive`, `Active`, `Deactivated`, `Compromised`, `Destroyed_Compromised`,
      - `<attributes>` is the KMIP Attributes structure (see the KMIP documentation)
      - `<wrapped_state>`: is a boolean indicating whether the object is wrapped or not (see key wrapping).

### Listing the access rights obtained by a user

A user can list all the access rights that have been granted to it by object owners.

=== "ckms"

      ```
      ➜ ckms access obtained --help
      List the access rights obtained by the calling user

      Returns a list of objects, their state, their owner and the accesses rights granted on the object

      Usage: ckms access obtained

      Options:
      -h, --help
            Print help (see a summary with '-h')
      ```

=== "REST"

      `GET` to the `/access/obtained` endpoint:

      The response is a JSON array:

      ```json
      [
            {
            "object_id": "the object unique identifier",
            "owner_id": "the user identifier of the owner of the object",
            "state": "<state>",
            "operations": [ <operation type> ]
            "attributes": "<attributes>",
            }
      ]
      ```

      where:

      - `<state>` is one of the following KMIP states: `PreActive`, `Active`, `Deactivated`, `Compromised`, `Destroyed_Compromised`,
      - `<operation type>` is one of the following: `export`, `get`, `encrypt`, `decrypt`, `import`, `revoke`,  `destroy`,
      - `<wrapped_state>`: is a boolean indicating whether the object is wrapped or not (see key wrapping).
