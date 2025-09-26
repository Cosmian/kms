
The SoftHSMv2 integration is supported on **Linux (x86_64)**.

### SoftHSMv2 library setup

To use SoftHSMv2 with the KMS, the library must first be installed.

The KMS expects the library to be installed at `/usr/lib/softhsm/libsofthsm2.so`.

Install the library using your distributions package manager, or build it by following the instructions in the [SoftHSMv2 GitHub repository](https://github.com/softhsm/SoftHSMv2).

### SoftHSMv2 initialisation

Before use, SoftHSMv2 requires initialization:

```shell
softhsm2-util --init-token --slot 0 --so-pin 000000 --pin 000000 --label "SoftHSM"
```

> **_NOTE:_** The slot number will be reassigned randomly. Use the new slot number in your KMS configuration.

### KMS configuration

At least one slot and its corresponding PIN must be configured.
Multiple slots can be used at the same time.

#### Configuration via config file
When using the [TOML configuration file](../server_configuration_file.md#toml-configuration-file), enable HSM support by setting these parameters:

```toml
hsm_model = "softhsm2"
hsm_admin = "<HSM_ADMIN_USERNAME>" # defaults to "admin"
hsm_slot = [0, 0, ] # example [0,4] for slots 0 and 4
hsm_password = ["<password>", "<password>", ] # example ["000000", "444444"] for slots 0 and 4
```
> **_NOTE:_**  hsm_slot and hsm_password must always be arrays, even if only one slot is used.

#### Configuration via command-line
HSM support can also be enabled with command-line arguments:
```shell
--hsm-model "softhsm2" \
--hsm-admin "<HSM_ADMIN_USERNAME>"  \
--hsm-slot <number_of_1st_slot> --hsm-password <password_of_1st_slot> \
--hsm-slot <number_of_2and_slot> --hsm-password <password_of_2and_slot>
```

The `hsm-model` parameter is the HSM model. Use `softhsm2`.

The `hsm-admin` parameter is the username of the HSM administrator.
The HSM administrator is the only user who can create objects on the HSM via the KMIP `Create` operation
and delegate other operations to other users.

The `hsm-slot` and `hsm-password` parameters are the slot number and user password (PIN) of the HSM slots used by the KMS.
These options can be repeated to configure multiple slots.

> **_NOTE:_** To list available slots, run:
> ```shell
> softhsm2-util --show-slots
> ```