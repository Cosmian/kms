# Trustway Proteccio

Eviden KMS natively integrates with the [Trustway Proteccio](https://eviden.com/solutions/digital-security/data-encryption/trustway-proteccio-nethsm/) HSM.

## Proteccio library setup

This solution works on Linux (x86_64) and has been validated against the Proteccio `nethsm` library version 3.17.

The KMS expects:

- the Proteccio `nethsm` library to be installed in `/lib/libnethsm.so`
- and the Proteccio configuration files in `/etc/proteccio`.

### `/etc/proteccio` configuration files

The Proteccio client library reads its configuration from `/etc/proteccio`. The directory must contain the
following files:

| File | Description |
|---|---|
| `proteccio.rc` or `proteccio.ini` | Main INI configuration file (see below) |
| `proteccio.crt` | Server TLS certificate (PEM) used to authenticate the HSM appliance |
| `proteccio_client.key` | Client TLS private key (PEM) for mutual TLS authentication |
| `proteccio_client.crt` | Client TLS certificate (PEM) for mutual TLS authentication |
| `secchannel_hsm.pem` | HSM secure-channel public key (EC, PEM) — only if the secure channel is enabled |
| `secchl_clt_privkey.pem` | Client secure-channel private key (PEM) — only if the secure channel is enabled |
| `secchl_clt_pubkey.pem` | Client secure-channel public key (PEM) — only if the secure channel is enabled |

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

!!! note "Note"

    All filenames in the configuration file are relative to `/etc/proteccio` unless an
    absolute path is given.

A secondary status log (`HSM_Status.log`) is written to `/etc/proteccio` by the `nethsmstatus`
monitoring daemon and records HSM availability events. It is not read by the KMS.

Please run the `nethsmstatus` tool to check the status of the HSM before proceeding with the
rest of the installation.

### Installing the client on Debian (x86_64)

The Proteccio client package ships an interactive `Linux/install.sh` (root, language prompt). The same result
can be obtained non-interactively with the steps below, which were validated on Debian 13 against a
Proteccio running firmware 194 (client library `nethsm` 4.5, PKCS#11 token flags `login required`).

1. Unpack the package delivered by Eviden and locate the 64-bit client files in `Client_Software/linux64`
   (`libnethsm.so`, `nethsmstatus`, `nethsmtool`). Keep the client certificate pair and the HSM server
   certificate provided with your HSM (`proteccio_client.crt`, `proteccio_client.key`, server `.crt`).

2. Install the library and tools:

    ```bash
    sudo cp Client_Software/linux64/libnethsm.so /lib/libnethsm.so
    sudo ln -sf /lib/libnethsm.so /usr/lib/libnethsm.so
    sudo install -m 755 Client_Software/linux64/nethsmstatus /usr/local/bin/nethsmstatus
    sudo install -m 755 Client_Software/linux64/nethsmtool   /usr/local/bin/nethsmtool
    ```

    `nethsmstatus` is linked against `libnethsm.so`; it fails with `libnethsm.so => not found` until the
    library is installed in a standard library path.

3. Install the certificates in `/etc/proteccio`. The HSM server certificate **must** be renamed
   `proteccio.crt` to match `SrvCert`:

    ```bash
    sudo mkdir -p /etc/proteccio
    sudo cp <server_cert>.crt        /etc/proteccio/proteccio.crt
    sudo cp proteccio_client.crt     /etc/proteccio/proteccio_client.crt
    sudo cp proteccio_client.key     /etc/proteccio/proteccio_client.key
    sudo chmod 644 /etc/proteccio/proteccio.crt /etc/proteccio/proteccio_client.crt
    sudo chmod 600 /etc/proteccio/proteccio_client.key
    ```

4. Create `/etc/proteccio/proteccio.ini` and copy it to `proteccio.rc` (the library reads `proteccio.rc`,
   as printed by `nethsmstatus`). The package default points at `192.168.0.1` with `SSL=0`: replace the
   address and enable TLS.

    ```ini
    [PROTECCIO]
    IPaddr=<HSM_IP_ADDRESS>
    SSL=1
    SrvCert=proteccio.crt

    [CLIENT]
    Mode=0
    LoggingLevel=0
    LogFile=/dev/null
    StatusFile=/dev/null
    ClntKey=proteccio_client.key
    ClntCert=proteccio_client.crt
    ```

    ```bash
    sudo cp /etc/proteccio/proteccio.ini /etc/proteccio/proteccio.rc
    ```

    !!! warning "Keep `LoggingLevel=0` for production and benchmarks"

        The Proteccio manual states that enabling traces has a direct impact on performance
        (`LoggingLevel` ranges from 0, no trace, to 7). Use a non-zero level only while debugging.

5. Check connectivity and the virtual HSMs (slots):

    ```bash
    nethsmstatus
    ```

    The command must print `TLS is enabled`, `Token state: 0X40 OPERATIONAL` and one `Token (Slot N)` block
    per virtual HSM, with its label. The `N` shown is the slot number to configure in `hsm_slot`.

6. Optionally verify the PKCS#11 login of one slot with `pkcs11-tool` (package `opensc`). Run it **once**:
   repeated failed logins can lock the virtual HSM.

    ```bash
    pkcs11-tool --module /lib/libnethsm.so --list-slots
    pkcs11-tool --module /lib/libnethsm.so --slot <0xN> --login --pin <password> --list-objects
    ```

    `pkcs11-tool --slot` expects the PKCS#11 slot ID (hexadecimal): Proteccio slot `4` is `0x4`, whereas
    `--slot-index` is zero-based (slot `4` is index `3`).

### Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `libnethsm.so => not found` when running `nethsmstatus` | Library not in `/lib` or `/usr/lib`; redo step 2 |
| Client cannot reach the HSM | Check `IPaddr`, TCP port 5552 (TLS) or 5551 (plain) through firewalls |
| TLS handshake fails | Server certificate not named `proteccio.crt`, or the client certificate is not imported on the HSM |
| Very low signature throughput | `LoggingLevel` is not `0`; see step 4 |

## KMS configuration

At least one slot and its corresponding password must be configured. Any slot and any number of slots may be used.

When using the [TOML configuration file](../configuration/server_configuration_file.md#toml-configuration-file), the HSM support
is enabled by configuring these 4 parameters:

```toml
hsm_model = "proteccio"
hsm_admin = "<HSM_ADMIN_USERNAME>" # defaults to "admin"
hsm_slot = [0, 0, ] # example [1,4] for slots 1 and 4
hsm_password = ["<password>", "<password>", ] # example ["pass1", "pass4"] for slots 1 and 4
```

!!! warning "Warning"

    `hsm_slot` and `hsm_password` must always be arrays, even if only one slot is used.

    The order of the passwords must match the order of the slots in the `hsm_slot` array.
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

## Kubernetes (Helm chart)

Use an official KMS image unmodified (`ghcr.io/cosmian/kms-fips` below, or `ghcr.io/cosmian/kms`).
An init container copies `libnethsm.so` from a small client image, and `/etc/proteccio` is mounted
from a Kubernetes Secret. See the [Helm chart HSM overview](../integrations/kubernetes/helm.md#hsm).
The `nethsm` client library links only against glibc (`libc.so.6`, `libdl.so.2`; check yours with
`readelf -d libnethsm.so`), so no extra runtime library is needed.

!!! warning "FIPS image: `command` override"
    `libnethsm.so` embeds its own OpenSSL, which reads the `OPENSSL_CONF` environment variable. The
    FIPS image sets it to the KMS FIPS configuration, which the embedded OpenSSL cannot load:
    `C_Initialize` fails with `CKR_FUNCTION_FAILED` and the pod restarts in a loop. The values below
    therefore start the KMS with `command: [env, -u, OPENSSL_CONF, cosmian_kms]`: the KMS then
    reads the same FIPS configuration from its built-in default path, and `libnethsm.so` uses its
    own defaults. The chart `command` value is available in chart releases after 5.28.0. The
    non-FIPS image (`ghcr.io/cosmian/kms`) does not need `command`.

!!! note
    Validated on minikube against a live Proteccio (secure channel enabled) with the values below,
    with the FIPS image (with `command`) and the non-FIPS image (without): HSM key creation, AES-GCM
    encryption and decryption through the KMS pod.

### 1. Proteccio client image

Build it once per `nethsm` version, from `Client_Software/linux64/libnethsm.so` of the Proteccio
package:

```dockerfile
FROM debian:bookworm-slim
COPY libnethsm.so /opt/proteccio/lib/libnethsm.so
```

### 2. Proteccio configuration in Secrets

The Secret is mounted read-only, so the library must not write logs into `/etc/proteccio`. Keep
`LogFile` and `StatusFile` on `/dev/null`. `proteccio.rc`:

```ini
[PROTECCIO]
IPaddr=<HSM_IP_ADDRESS>
SSL=1
SrvCert=proteccio.crt

[CLIENT]
Mode=0
LoggingLevel=0
LogFile=/dev/null
StatusFile=/dev/null
ClntKey=proteccio_client.key
ClntCert=proteccio_client.crt
```

```bash
kubectl -n kms create secret generic proteccio-files \
  --from-file=proteccio.rc \
  --from-file=proteccio.crt=<server_cert>.crt \
  --from-file=proteccio_client.crt \
  --from-file=proteccio_client.key
kubectl -n kms create secret generic proteccio-password --from-literal=password='<password>'
```

With the secure channel enabled (`SEC_CHANNEL=1`), also add `secchannel_hsm.pem`,
`secchl_clt_privkey.pem` and `secchl_clt_pubkey.pem` to the Secret and their keys to `proteccio.rc`
(see [`/etc/proteccio` configuration files](#etcproteccio-configuration-files)).

### 3. Helm values

```yaml
image:
  repository: ghcr.io/cosmian/kms-fips
  tag: <version>
nodeSelector: {kubernetes.io/arch: amd64} # the proteccio model is Linux x86_64 only
command: [env, -u, OPENSSL_CONF, cosmian_kms] # FIPS image only, see above
extraArgs: [--hsm-model, proteccio, --hsm-slot, "<slot>", --hsm-admin, admin]
extraEnv:
  - name: PROTECCIO_PKCS11_LIB
    value: /opt/proteccio/lib/libnethsm.so
  - name: KMS_HSM_PASSWORD
    valueFrom:
      secretKeyRef: {name: proteccio-password, key: password}
initContainers:
  - name: proteccio-client
    image: <registry>/proteccio-client:<nethsm-version>
    command: [cp, /opt/proteccio/lib/libnethsm.so, /proteccio-client/]
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
    volumeMounts:
      - {name: proteccio-client, mountPath: /proteccio-client}
extraVolumes:
  - name: proteccio-client
    emptyDir: {}
  - name: proteccio
    secret:
      secretName: proteccio-files
      defaultMode: 0440
extraVolumeMounts:
  - name: proteccio-client
    mountPath: /opt/proteccio/lib
    readOnly: true
  - name: proteccio
    mountPath: /etc/proteccio
    readOnly: true
```

The pod must reach the HSM on TCP port 5552 (TLS).
