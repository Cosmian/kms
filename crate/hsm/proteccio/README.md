# Proteccio HSM wrapper

This is a wrapper for the Proteccio HSM library. It is written in Rust and provides a simple interface to the Proteccio
HSM library.

## Installation

The library must be installed at `/lib/libnethsm.so`

All other files shouold go to `/etgc/proteccio`
 - `proteccio.rc` is the configuration file
 - `proteccio.crt` is the certificate file of the (net) HSM
 - `proteccio_client.key` and `proteccio_client.crt` are the client certificate and key for the HSM

The log file and log level are specified in the `proteccio.rc` files.
To view the logs use the command `tail -f /var/log/proteccio.log`

To verify the configuration:

```bash
> nethsmstatus
Read Proteccio Config from file: /etc/proteccio/proteccio.rc
TLS server certificate: /etc/proteccio/proteccio.crt

*******************************
HSM-1 IP address: 193.251.82.208
*******************************
TLS is enabled
manufacturer ID:        Bull Trustway Proteccio HSM
library Description:    nethsm PKCS#11 RPC
libraryVersion:         3.17
Token state:            0X40 OPERATIONAL
Extended state:         0X0
MCS Version:            65539
Firmware Version:       162
Flags:                  0X80000007 PROTECCIO HR
Serial Number:          81610-0040000161
  Token (Slot 1)
    Virtual HSM state:  0X40 OPERATIONAL
    Extended state:             0X0
    Flags               0X5
    Label:              HSM1-V1
...
```
To list tokens in a slot:

```bash
nethsmtool -l <slot_id> <slot_password>
```