## Authentication

The KMS server provides an authentication system using access tokens (signed JWT) compatible with Auth0.
See [Access Tokens](https://auth0.com/docs/secure/tokens#access-tokens)

The authority domain is configured on the server using the option:

```
--auth0-authority-domain <AUTH0_AUTHORITY_DOMAIN>
    Enable the use of Auth0 by specifying the delegated authority domain configured on Auth0
    
    [env: KMS_JWT_ISSUER_URI=]
```

The token is passed to the `/kmip_2_1` endpoint using the Authorization header:

```
Authorization: Bearer <TOKEN>
```

On the `cKMS` command line interface, the token is configured in the client configuration. Please refer to the [CLI documentation](cli/cli.md) for more details.



## Authorization

An object belongs to only one user called *owner* who is the creator of the object. This assignment can never be changed.
The owner can perform any kind of operation on the object.
By default, other users are not allowed to access and perform operations on that object.

The owner is the only one who can decide to share an object with another user. The owner permits the other user to perform some specifically defined [operations](kmip_2_1/operations.md) among the followings:

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

### Endpoint

The endpoint is `/accesses/{object_id}`. The following HTTP methods are available:

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
