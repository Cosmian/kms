Cosmian KMS natively integrates with the [Trustway Proteccio](https://eviden.com/solutions/digital-security/data-encryption/trustway-proteccio-nethsm/) HSM.

### Proteccio library setup

This solution works on Linux (x86_64) and has been validated against the Proteccio `nethsm` library version 3.17.

The KMS expects:

- the Proteccio `nethsm` library to be installed in `/lib/libnethsm.so`
- and the Proteccio configuration files in `/etc/proteccio`.

#### `/etc/proteccio` configuration files

The Proteccio client library reads its configuration from `/etc/proteccio`. The directory must contain the
following files:

| File | Description |
|---|---|
| `proteccio.rc` or `proteccio.ini` | Main INI configuration file (see below) |
| `proteccio.crt` | Server TLS certificate (PEM) used to authenticate the HSM appliance |
| `proteccio_client.key` | Client TLS private key (PEM) for mutual TLS authentication |
| `proteccio_client.crt` | Client TLS certificate (PEM) for mutual TLS authentication |
| `secchannel_hsm.pem` | HSM secure-channel public key (EC, PEM) |
| `secchl_clt_privkey.pem` | Client secure-channel private key (PEM) |
| `secchl_clt_pubkey.pem` | Client secure-channel public key (PEM) |

The `proteccio.rc` / `proteccio.ini` file contains two sections:

```ini
[PROTECCIO]
IPaddr=<HSM_IP_ADDRESS>   ; IP address of the Proteccio appliance
SSL=1                     ; Enable TLS (1) or plain TCP (0)
SrvCert=proteccio.crt     ; Server certificate filename (relative to /etc/proteccio)
SEC_CHANNEL=1             ; Enable encrypted secure channel (1) or not (0)
SecChlSrvKey=secchannel_hsm.pem  ; HSM secure-channel public key filename

[CLIENT]
Mode=0                    ; 0 = synchronous
LoggingLevel=7            ; Verbosity (0–7, 7 = most verbose)
LogFile=proteccio_log_file.log   ; Path to the library log file
ClntKey=proteccio_client.key     ; Client TLS private key filename
ClntCert=proteccio_client.crt    ; Client TLS certificate filename
SecChlClntPrivKey=secchl_clt_privkey.pem  ; Client secure-channel private key
SecChlClntPubKey=secchl_clt_pubkey.pem    ; Client secure-channel public key
```

> **_NOTE:_** All filenames in the configuration file are relative to `/etc/proteccio` unless an
> absolute path is given.

A secondary status log (`HSM_Status.log`) is written to `/etc/proteccio` by the `nethsmstatus`
monitoring daemon and records HSM availability events. It is not read by the KMS.

Please run the `nethsmstatus` tool to check the status of the HSM before proceeding with the
rest of the installation.

### KMS configuration

At least one slot and its corresponding password must be configured. Any slot and any number of slots may be used.

When using the [TOML configuration file](../configuration/server_configuration_file.md#toml-configuration-file), the HSM support
is enabled by configuring these 4 parameters:

```toml
hsm_model = "proteccio"
hsm_admin = "<HSM_ADMIN_USERNAME>" # defaults to "admin"
hsm_slot = [0, 0, ] # example [1,4] for slots 1 and 4
hsm_password = ["<password>", "<password>", ] # example ["pass1", "pass4"] for slots 1 and 4
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
--hsm-model "proteccio" \
--hsm-admin "<HSM_ADMIN_USERNAME>"  \
--hsm-slot <number_of_1st_slot> --hsm-password <password_of_1st_slot> \
--hsm-slot <number_of_2and_slot> --hsm-password <password_of_2and_slot>
```

The `hsm-model` parameter is the HSM model to be used; use `proteccio`

The `hsm-admin` parameter is the username of the HSM administrator. The HSM administrator is the only user that can create objects on the HSM via the KMIP `Create` operation the delegate other operations to other users. (see below)

The `hsm-slot` and `hsm-password` parameters are the slot number and password of the HSM slots to be used by the KMS. These arguments can be repeated multiple times to specify multiple slots.
