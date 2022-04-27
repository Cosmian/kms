# Object authorization policy

An object belongs to only one user called *owner* who is the creator of the object. This assignment can never be changed.
The owner can perform any kind of operations on the object.

By default other users are not allowed to access and perform operations on that object.

The owner is the only one who can decide to share an object with another user. The owner grants the other user the permission to perform some specifically defined [operations](kmip_2_1/operations.md) among the followings:

- [Create](kmip_2_1/operations.md#create)
- [Get](kmip_2_1/operations.md#get)
- [Encrypt](kmip_2_1/operations.md#encrypt)
- [Decrypt](kmip_2_1/operations.md#decrypt)
- [Locate](kmip_2_1/operations.md#locate)
- [Rekey](kmip_2_1/operations.md#re-key-key-pair)

The following operations are not sharable:

- [Import](kmip_2_1/operations.md#import)
- [Revoke](kmip_2_1/operations.md#revoke)
- [Destroy](kmip_2_1/operations.md#destroy)
- Delegate the ability to share the object (creation, updation or deletion)

These permissions are stored inside the KMS database.

The permission system relies on the email address stored in the [JWT token used to authenticate](api.md#authentication) the user when accessing the API.

## Endpoint

The endpoint is `/access`. Following HTTP methods are available:

- `DELETE` to remove a permission
- `POST` to grant a permission

The expecting data are serialized in JSON such as:

```json
{
   "userid": "email@example.com",
   "operation_type": "Get",
   "unique_identifier": "my-object-uuid"
}
```