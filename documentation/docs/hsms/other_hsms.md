Integration of other HSMs is supported on **Linux (x86_64)**.

Even if your HSM is not explicitly listed in this documentation, there is a great change that it will work, in
particular its PKCS#11 driver API is compatible with that of SofHsmV2.

### Library setup

The KMS expects the HSM linux PKCS#11 library to be installed at `/lib/libkmshsm.so`.
Rename your HSM library to `libkmshsm.so` if necessary.

### HSM initialization

Before using the HSM with the KMS, follow your documentation to initialize a slot and a user pin/password for that
slot.

### KMS configuration

At least one slot and its corresponding PIN must be configured.
Multiple slots can be used at the same time.

#### Configuration via config file

When using the [TOML configuration file](../server_configuration_file.md#toml-configuration-file), enable HSM support by
setting these parameters:

```toml
hsm_model = "other"
hsm_admin = "<HSM_ADMIN_USERNAME>" # defaults to "admin"
hsm_slot = [0, 0, ] # example [0,4] for slots 0 and 4
hsm_password = ["<password>", "<password>", ] # example ["000000", "444444"] for slots 0 and 4
```

> **_NOTE:_**  `hsm_slot` and `hsm_password` must always be arrays, even if only one slot is used.
>
> The order of the passwords must match the order of the slots in the `hsm_slot` array.
>
> If you want to login with an empty (null) password, use an empty string.
>
> If you do not want to login, use the special password value `<NO_LOGIN>`

#### Configuration via command-line

HSM support can also be enabled with command-line arguments:

```shell
--hsm-model "other" \
--hsm-admin "<HSM_ADMIN_USERNAME>"  \
--hsm-slot <number_of_1st_slot> --hsm-password <password_of_1st_slot> \
--hsm-slot <number_of_2and_slot> --hsm-password <password_of_2and_slot>
```

The `hsm-model` parameter is the HSM model. Use `other`.

The `hsm-admin` parameter is the username of the HSM administrator.
The HSM administrator is the only user who can create objects on the HSM via the KMIP `Create` operation
and delegate other operations to other users.

The `hsm-slot` and `hsm-password` parameters are the slot number and user password (PIN) of the HSM slots used by the
KMS.
These options can be repeated to configure multiple slots.
