# Permission Management

Manage the permission of objects.

```
ckms permission <COMMAND>
```

### list

List granted access authorizations for an object

**Usage:**
```
ckms permission list <OBJECT_UID>
```

**Arguments:**
```
<OBJECT_UID>  The object unique identifier stored in the KMS
```

**Options:**
```
  -h, --help  Print help
```

### add

Add an access authorization for an object to a user

**Usage:**
```
ckms permission add --user <USER> --operation <OPERATION> <OBJECT_UID>
```

**Arguments:**
```
<OBJECT_UID>  The object unique identifier stored in the KMS
```

**Options:**
```
-u, --user <USER>            The user to allow
-o, --operation <OPERATION>  The operation to allow (create, get, encrypt, decrypt, import, revoke, locate, rekey, destroy)
-h, --help                   Print help
```

### remove

Remove an access authorization for an object to a user

**Usage:**
```
ckms permission remove --user <USER> --operation <OPERATION> <OBJECT_UID>
```

**Arguments:**
```
<OBJECT_UID>  The object unique identifier stored in the KMS
```

**Options:**
```
-u, --user <USER>            The user to ungrant
-o, --operation <OPERATION>  The operation to remove (create, get, encrypt, decrypt, import, revoke, locate, rekey, destroy)
-h, --help                   Print help
```

### owned

List objects owned by the current user

**Usage:**
```
ckms permission owned
```

**Options:**
```
-h, --help  Print help
```

### shared

List objects shared for the current user

**Usage:**
```
ckms permission shared
```

**Options:**
```
-h, --help  Print help
```

### help

Print the help message or the help of the given subcommand(s).

```
ckms permission help [SUBCOMMAND]
```
```

