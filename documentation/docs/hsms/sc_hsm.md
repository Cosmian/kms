
The Smartcard HSM integration is supported on **Linux (x86_64)**.
It has been tested with the following devices:

- **SC HSM 4k** (Smartcard and USB variants)
- **Nitrokey HSM 2**

### Smartcard HSM library setup

To use a Smartcard HSM with the KMS, the **`sc-hsm-embedded` PKCS#11 library** must be installed.
The integration has been validated with **version 2.12**.

The KMS expects the library to be installed at `/usr/local/lib/libsc-hsm-pkcs11.so`.

To build and install the library, follow the instructions in the [sc-hsm-embedded GitHub repository](https://github.com/CardContact/sc-hsm-embedded).

### Smartcard HSM initialisation

> ⚠️ **Warning:**
>
> - Initialization is **destructive**. It will erase all existing keys and objects on the HSM.
> - Losing the **Security Officer (SO) PIN** will prevent future resets of the HSM. This can make the device permanently unusable. Keep it secure.
>
> **_NOTE:_**
> The default PINs shown below are recommended by the manufacturer for development purposes. Always change them in production.

Before use, the HSM must be initialized. There are two ways to accomplish this:

#### Graphical Initialization (SmartCard-HSM Key Manager)

1. Download and install [Smart Card Shell](https://www.openscdp.org/scsh3/download.html).
2. Launch Smart Card Shell and insert the HSM.
3. From the **File** menu (or with `CTRL+M`), open the **SmartCard-HSM Key Manager**.
4. Right-click on the HSM entry and select **Initialize Device**.
5. Follow the on-screen guide.

#### Using sc-hsm-tool

1. Install the [OpenSC for your distribution](https://github.com/OpenSC/OpenSC/wiki/Linux-Distributions).

2. Initialize the card with a Security Officer and a User PIN.

   ```shell
   sc-hsm-tool --initialize --so-pin 3537363231383830 --pin 648219 --label "SC HSM test"
   ```

   Additional initialisation options are [documented in the sc-hsm-tool man page](https://manpages.ubuntu.com/manpages/en/man1/sc-hsm-tool.1.html).

### KMS configuration

At least one slot and its corresponding PIN must be configured.
Multiple slots can be used simultaneously, with each represented by a separate slot.

#### Configuration via config file

When using the [TOML configuration file](../server_configuration_file.md#toml-configuration-file), enable HSM support by setting these parameters:

```toml
hsm_model = "smartcardhsm"
hsm_admin = "<HSM_ADMIN_USERNAME>" # defaults to "admin"
hsm_slot = [0, 0, ] # example [0,4] for slots 0 and 4
hsm_password = ["<password>", "<password>", ] # example ["648219", "648219"] for slots 0 and 4
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
--hsm-model "smartcardhsm" \
--hsm-admin "<HSM_ADMIN_USERNAME>"  \
--hsm-slot <number_of_1st_slot> --hsm-password <password_of_1st_slot> \
--hsm-slot <number_of_2and_slot> --hsm-password <password_of_2and_slot>
```

The `hsm-model` parameter is the HSM model. Use `smartcardhsm`.

The `hsm-admin` parameter is the username of the HSM administrator.
The HSM administrator is the only user who can create objects on the HSM via the KMIP `Create` operation
and delegate other operations to other users.

The `hsm-slot` and `hsm-password` parameters are the slot number and user password (PIN) of the HSM slots used by the KMS.
These options can be repeated to configure multiple slots.

> **_NOTE:_** To list available slots, run:
>
> ```shell
> pkcs11-tool --module /usr/local/lib/libsc-hsm-pkcs11.so --list-slots
> ```
