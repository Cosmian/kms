
This solution works on Linux (x86_64) and has been validated against the Utimaco client library version 6.0.

### Utimaco library setup

This solution works on Linux (x64_86) and has been validated against the Utimaco `libcs_pkcs11_R3.so` library version 6.0.

The KMS expects:

- the Utimaco `cs_pkcs11_R3` library to be installed in `/lib/libcs_pkcs11_R3.so`
- the Utimaco configuration file `cs_pkcs11_R3.cfg` to be in `/etc/utimaco` and
- and the environment variable `CS_PKCS11_R3_CF` to point to it, i.e.,

```sh
export CS_PKCS11_R3_CFG=/etc/utimaco/cs_pkcs11_R3.cfg
```

Please make sure the `cs_pkcs11_R3.cfg` is set with the correct parameter, and validate your
installation with the `p11tool2` utility, by running, for instance,

```sh
./p11tool2 Slot=0 GetSlotInfo
```

### KMS configuration

At least one slot and its corresponding password must be configured. Any slot and any number of slots may be used.

When using the [TOML configuration file](../server_configuration_file.md#toml-configuration-file), the HSM support is enabled by configuring these 4 parameters:

```toml
hsm_model = "utimaco"
hsm_admin = "<HSM_ADMIN_USERNAME>" # defaults to "admin"
hsm_slot = [0, 0, ] # example [0,4] for slots 0 and 4
hsm_password = ["<password>", "<password>", ] # example ["pass0", "pass4"] for slots 0 and 4
```

> **_NOTE:_**  `hsm_slot` and `hsm_password` must always be arrays, even if only one slot is used.
>
> The order of the passwords must match the order of the slots in the `hsm_slot` array.
>
> If you want to login with an empty (null) password, use an empty string.
>
> If you do not want to login, use the special password value `<NO_LOGIN>`

When the KMS is started from the command line, the HSM support can be enabled by using the following arguments:

```shell
--hsm-model "utimaco" \
--hsm-admin "<HSM_ADMIN_USERNAME>"  \
--hsm-slot <number_of_1st_slot> --hsm-password <password_of_1st_slot> \
--hsm-slot <number_of_2and_slot> --hsm-password <password_of_2and_slot>
```

The `hsm-model` parameter is the HSM model; use `utimaco`.

The `hsm-admin` parameter is the username of the HSM administrator.
The HSM administrator is the only user who can create objects on the HSM via the KMIP `Create` operation
and delegate other operations to other users.
(see below)

The `hsm-slot` and `hsm-password` parameters are the slot number and user password of the HSM slots used by the KMS.
These arguments can be repeated multiple times to specify various slots.

### Using the simulator

Utimaco provides a simulator that can be used instead of a physical HSM to test your installation.
The simulator is a 32-bit Linux i386 library (it also exists as a Windows binary).

Follow these general steps to install the simulator on a Debian-based (e.g., Ubuntu) Linux amd64/x86_64.

1. Enable 32-bit support

    ```bash
    sudo dpkg --add-architecture i386
    ```

    Then

    ```bash
    sudo apt-get update
    sudo apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386
    ```

2. Start the simulator

    In `<eval-bundle-6.0.0>\Software\Windows\Simulator\sim5_windows\bin`, run

    ```sh
    .\bl_sim5.exe -h -o -d ..\devices\
    ```

3. Make sure the Device in `cs_pkcs11_R3.cfg` points to the simulator.

4. Initialize a slot and create the Security Officer and User pins.

    Due to a bug (?) in the simulator,
   the Security Officer PIN must be set **then changed** before the User PIN can be set,
   and **then changed** as well.

    ```bash
    # Set the SO PIN to 11223344
    ./p11tool2 Slot=0 login=ADMIN,./key/ADMIN_SIM.key  InitToken=11223344
    # Change the SO PIN to 12345678
    ./p11tool2 Slot=0 LoginSO=11223344 SetPin=11223344,12345678
    ```

    Failing to change the SO PIN before setting the User PIN will result in the following error: `Error 0x000001B8 (
    CKR_PIN_TOO_WEAK)`

    ```bash
    # Set the User PIN to 11223344
    ./p11tool2 Slot=0 LoginSO=12345678 InitPin=11223344
    # Change the User PIN to 12345678
    ./p11tool2 Slot=0 LoginUser=11223344 SetPin=11223344,12345678
    ```

    Now, both the SO and User PINs have been set to 12345678.

    To list objects on Slot 0, use:

    ```bash
    ./p11tool2 Slot=0 LoginUser=12345678 ListObjects
    ```
