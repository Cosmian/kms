
The Smartcard HSM integration is supported on **Linux (x86_64)**.
It has been tested with the following devices: BULL PKCS11 C2P 5.0.7 (Release) Unix64

## HSM files installation

### Copy the Crypt2pay PKCS#11 library to `/lib`

Copy `libpkcs11c2p.so` to `/lib`.
Make sure it is readable by the user running the KMS.

### Create the `c2p` directory

Create a `c2p` directory in, say, `/etc/c2p` (hereafter called `[C2P_DIR]`)

In this directory copy the following files:

- `c2padmin`   <- The Crypt2pay admin tool
- `c2p.xml`    <- The Crypt2pay configuration file
- `ca.der`     <- The CA certificate
- `installca`  <- The Crypt2pay CA installation tool
- `p11tool`    <- The PKCS#11 tool used to test the connection
- The two files with extensions `.kdk` and `.ksk` <- The client key files

### Install the CA certificate

This certificate is the one that signed the HSM certificate and will be used to authenticate the HSM.
In the `[C2P_DIR]`, run the `installca` tool:

```sh
./installca -i ./ca.der ssl
```

This will create an `ssl` directory in the `[C2P_DIR]` and copy the CA certificate there.
To check that the CA certificate is installed correctly, run:

```sh
./installca -l ./ssl/
```

Edit the `c2p.xml` file and insert the full path to the CA certificate `ssl` directory in `C2Pconfig/sslDefinition/Authorities`:

```xml
<C2Pconfig>
  ...
  <sslDefinition>
   <Authorities>[C2P_DIR]/ssl</Authorities>
  </sslDefinition>
  ...
</C2Pconfig>
```

replace `[C2P_DIR]` with the actual path.

### Set logging and Verify the `c2p.xml` file

In the `c2p.xml` file, set the logging to

```xml
<C2Pconfig>
  <TraceLevel>debug functions parameters pkcs hsm</TraceLevel>
  <TraceFile>+logs\c2p.trc</TraceFile>
  ...
</C2Pconfig>
```

Check the Crypt2pay manual to make sure that other elements of the `c2p.xml` are correct, in particular,

- the name of the `. ksk` file in `C2Pconfig/KSKfile`
- the name of the `. kdk` file in `C2Pconfig/C2pSlot/C2PBox/KDKfile`
- the IP address of the HSM in `C2Pconfig/C2pSlot/C2PBox/IP`

.. and recover the configured Slot ID(s) in `C2Pconfig/C2pSlot[Id]"`

**IMPORTANT NOTE:** The configuration above authenticates the HSM only.
To configure mutual authentication with mTLS, additional configuration is required.
Check the Crypt2pay manual for details.

### Set the `C2P_CONF` environment variable to `[C2P_DIR]/c2p.xml`

```sh
export C2P_CONF=[C2P_DIR]/c2p.xml
```

replace `[C2P_DIR]` with the actual path.

### Test the configuration

Run the `p11tool` tool to create a new 256-bit AES key:

```shell
./p11tool -genkey -keyalg aes -keysize 256 -shared /lib/libpkcs11c2p.so -slot 1 -verbose
```

The creation should be successful and print the key alias and ID:

```shell
use slot #1
Alias 'mykey' selected
Secret key #1000004 created
```

The logs are available in `[C2P_DIR]/logs/c2p.trc`.

## KMS Configuration

When using the [TOML configuration file](../server_configuration_file.md#toml-configuration-file), enable HSM support by setting these parameters:

```toml
hsm_model = "crypt2pay"
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

### Configuration via command-line

HSM support can also be enabled with command-line arguments:

```shell
--hsm-model "crypt2pay" \
--hsm-admin "<HSM_ADMIN_USERNAME>"  \
--hsm-slot <number_of_1st_slot> --hsm-password <password_of_1st_slot> \
--hsm-slot <number_of_2and_slot> --hsm-password <password_of_2and_slot>
```

The `hsm-model` parameter is the HSM model. Use `crypt2pay`.

The `hsm-admin` parameter is the username of the HSM administrator.
The HSM administrator is the only user who can create objects on the HSM via the KMIP `Create` operation
and delegate other operations to other users.

The `hsm-slot` and `hsm-password` parameters are the slot number and user password (PIN) of the HSM slots used by the KMS.
These options can be repeated to configure multiple slots.

> **_NOTE:_** To list available slots and keys run from the `[C2P_DIR]` directory:
>
> ```shell
> ./p11tool -list -shared /lib/libpkcs11c2p.so -verbose
> ```
