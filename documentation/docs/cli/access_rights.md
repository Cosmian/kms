# Access Rights Management

Manage the users' access rights to the cryptographic objects

Please check the [authorization documentation](../authorization.md) for more information.

```
ckms access <COMMAND>
```

### grant

Grant another user an access right to an object.

This command can only be called by the owner of the object.

The right is granted for one of the supported KMIP operations: create, get, encrypt, decrypt, import, revoke, locate, rekey, destroy

**Usage:**
```
ckms access grant <USER> <OBJECT_UID> <OPERATION>
```

**Arguments:**
```
<USER>
          The user identifier to allow

<OBJECT_UID>
          The object unique identifier stored in the KMS

<OPERATION>
          The KMIP operation to allow
```

**Options:**
```
-h, --help
          Print help (see a summary with '-h')
```

### revoke

Revoke another user access right to an object.

This command can only be called by the owner of the object.

**Usage:**
```
ckms access revoke <USER> <OBJECT_UID> <OPERATION>
```

**Arguments:**
```
<USER>
          The user to revoke access to

<OBJECT_UID>
          The object unique identifier stored in the KMS

<OPERATION>
          The operation to revoke (create, get, encrypt, decrypt, import, revoke, locate, rekey, destroy)
```

**Options:**
```
-h, --help
          Print help (see a summary with '-h')
```

### list

List the access rights granted on an object to other users.

This command can only be called by the owner of the object. Returns a list of users and the operations they have been granted access to.

**Usage:**
```
ckms access list <OBJECT_UID>
```

**Arguments:**
```
<OBJECT_UID>
          The object unique identifier
```

**Options:**
```
-h, --help
          Print help (see a summary with '-h')
```

### owned

List the objects owned by the calling user.

Owners of objects can perform any operation on these objects and can grant access rights on any of these operations to any other user.

**Usage:**
```
ckms access owned
```

**Options:**
``` 
-h, --help
          Print help (see a summary with '-h')
```

### obtained

List the access rights obtained by the calling user

Returns a list of objects, their state, their owner and the accesses rights granted on the object

**Usage:**
```
ckms access obtained
```

**Options:**
```
-h, --help
      Print help (see a summary with '-h')
```