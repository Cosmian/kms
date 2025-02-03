Cosmian KMS natively integrates with
the [Trustway Proteccio](https://eviden.com/solutions/digital-security/data-encryption/trustway-proteccio-nethsm/) HSM.

### Proteccio library setup

This solution works on Linux (x86_64) and has been validated against the Proteccio `nethsm` library version 3.17.

The KMS expects:

- the Proteccio `nethsm` library to be installed in `/lib/libnethsm.so`
- and the Proteccio configuration files in `/etc/proteccio`.

Please run the `nethsmstatus` tool to check the status of the HSM before proceeding with the
rest of the installation.

### KMS configuration

At least one slot and its corresponding password must be configured. Any slot and any number of slots may be used.

When using the [TOML configuration file](../server_configuration_file.md#toml-configuration-file), the HSM support
is enabled by configuring these 4 parameters:

```toml
hsm_model = "proteccio"
hsm_admin = "<HSM_ADMIN_USERNAME>" # defaults to "admin" 
hsm_slot = [0, 0, ] # example [1,4] for slots 1 and 4
hsm_password = ["<password>", "<password>", ] # example ["pass1", "pass4"] for slots 1 and 4
```

Even if only one slot is used, the `hsm_slot` and `hsm_password` parameters must be arrays.

When the KMS is started from the command line, the HSM support can be enabled by using the following arguments:

```shell
--hsm-model "proteccio" \
--hsm-admin "<HSM_ADMIN_USERNAME>"  \
--hsm-slot <number_of_1st_slot> --hsm-password <password_of_1st_slot> \
--hsm-slot <number_of_2nd_slot> --hsm-password <password_of_2nd_slot>
```

The `hsm-model` parameter is the HSM model to be used; use `proteccio`

The `hsm-admin` parameter is the username of the HSM administrator. The HSM administrator is the only user that can create objects on the HSM via the KMIP `Create` operation the delegate other operations to other users. (see below)

The `hsm-slot` and `hsm-password` parameters are the slot number and password of the HSM slots to be used by the KMS. These arguments can be repeated multiple times to specify multiple slots.


