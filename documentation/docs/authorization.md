# KMS Authorizing users with access objects

When [authentication](./authentication.md) is enabled, each KMS object requires explicit authorization from its owner to be accessed or used by others.
The Cosmian CLI then allows to manage the access rights of users to cryptographic objects stored in the KMS.

## Granting an access right

An owner of an object grants an access right to a specific user for a given operation on a given object.
The supported KMIP operations are: `get`, `export`, `encrypt`, `decrypt`, `import`, `revoke`, `destroy`.

=== "cosmian"

      ```
      ➜ cosmian kms access grant --help
      Grant another user an access right to an object.

      This command can only be called by the owner of the object.

      The right is granted for one of the supported KMIP operations: create, get, encrypt, decrypt, import, revoke, locate, rekey, destroy

      Usage: cosmian kms access grant <USER> <OBJECT_UID> <OPERATION>

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

## Revoking an access right

An owner of an object can revoke an access right to a specific user for a given operation on a given object at any time.

=== "cosmian"

      ```
      ➜ cosmian kms access revoke --help
      Revoke another user access right to an object.

      This command can only be called by the owner of the object.

      Usage: cosmian kms access revoke <USER> <OBJECT_UID> <OPERATION>

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

## Listing an object access rights

The owner of an object can list all the access rights that have been granted to another object.

=== "cosmian"

      ```
      ➜ cosmian kms access list --help
      List the access rights granted on an object to other users.

      This command can only be called by the owner of the object. Returns a list of users and the operations they have been granted access to.

      Usage: cosmian kms access list <OBJECT_UID>

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

## Listing the objects owned by a user

A user can list all the objects it owns (i.e. the objects it created using either the `Create`, `CreateKeyPair`,
or `Import` KMIP operations).

=== "cosmian"

      ```
      ➜ cosmian kms access owned --help
      List the objects owned by the calling user.

      Owners of objects can perform any operation on these objects and can grant access rights on any of these operations to any other user.

      Usage: cosmian kms access owned

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
            "is_wrapped": "<wrapped_state>"
         }
      ]
      ```

      where:

      - `<state>` is one of the following KMIP states: `PreActive`, `Active`, `Deactivated`, `Compromised`, `Destroyed_Compromised`,
      - `<attributes>` is the KMIP Attributes structure (see the KMIP documentation)
      - `<wrapped_state>`: is a boolean indicating whether the object is wrapped or not (see key wrapping).

## Listing the access rights obtained by a user

A user can list all the access rights that have been granted to it by object owners.

=== "cosmian"

      ```
      ➜ cosmian kms access obtained --help
      List the access rights obtained by the calling user

      Returns a list of objects, their state, their owner and the accesses rights granted on the object

      Usage: cosmian kms access obtained

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
            "is_wrapped": "<wrapped_state>"
            }
      ]
      ```

      where:

      - `<state>` is one of the following KMIP states: `PreActive`, `Active`, `Deactivated`, `Compromised`, `Destroyed_Compromised`,
      - `<operation type>` is one of the following: `export`, `get`, `encrypt`, `decrypt`, `import`, `revoke`,  `destroy`,
      - `<wrapped_state>`: is a boolean indicating whether the object is wrapped or not (see key wrapping).
