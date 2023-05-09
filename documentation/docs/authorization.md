### Ownership and permissions

In the system, each object belongs to a single user, known as the *owner*. The owner is the creator of the object, and this relationship cannot be changed. By default, the owner has full control over the object and can perform any operation on it. Other users do not have access to the object unless granted permission by the owner.

### Sharing objects

The owner is the only user who can decide to share an object with another user. When sharing an object, the owner can grant specific permissions to the other user, allowing them to perform certain [operations](kmip_2_1/operations.md) on the object, such as:

- [Create](kmip_2_1/operations.md#create)
- [Get](kmip_2_1/operations.md#get)
- [Encrypt](kmip_2_1/operations.md#encrypt)
- [Decrypt](kmip_2_1/operations.md#decrypt)
- [Locate](kmip_2_1/operations.md#locate)
- [Rekey](kmip_2_1/operations.md#re-key-key-pair)

However, there are some operations that cannot be shared:

- [Import](kmip_2_1/operations.md#import)
- [Revoke](kmip_2_1/operations.md#revoke)
- [Destroy](kmip_2_1/operations.md#destroy)
- Delegating the ability to share the object (creation, update, or deletion)

These permissions are stored in the KMS database and enforced when a user attempts to access an object.

### Authentication and authorization

The permission system relies on the email address stored in the [JWT token](./authentication) used to authenticate the user when accessing the API. When a user attempts to perform an operation on an object, the system checks the JWT token's email address to determine whether the user has the necessary permissions to perform the requested operation.

## Calling the permissions endpoint

The easiest way to view and set permissions is to use the [`cKMS`](./cli/permissions.md) CLI. However, you can also call the permissions endpoint directly: `/accesses/{object_id}`. The following HTTP methods are available:

- `DELETE` to remove a permission
- `POST` to grant a permission

The expected data are serialized in JSON such as:

```json
{
   "userid": "email@example.com",
   "operation_type": "Get",
   "unique_identifier": "my-object-uuid"
}
```

You can also list the accesses of an object using `/accesses/{object_id}` route with `GET` method. The output will be:

```json
[
   ["user@exemple.com", ["Get", "Revoke"]],
   ["user2@exemple.com", ["Create", "Revoke"]],
   ...
]
```

You can list the objects you own using  `/objects/owned` route with `GET` method. The output will be:

```json
[
   ["object-id-1", "Active"],
   ["object-id-2", "Active"],
   ...
]
```

You can list the objects someone shared with you using  `/objects/shared` route with `GET` method. The output will be:

```json
[
   ["object-id-1", "user@example.com", "Active", ["Get", "Revoke"]],
   ["object-id-2", "user@example.com", "Active", ["Revoke"]],
   ...
]
```
