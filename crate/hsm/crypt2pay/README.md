# Crypt2pay HSM wrapper

This is a wrapper for the Crypt2pay HSM library. It is written in Rust and provides a simple interface to the Crypt2pay
HSM library.

## Installation

The library must be installed at `/lib/libnethsm.so`

All other files shouold go to `/etgc/crypt2pay`

- `crypt2pay.rc` is the configuration file
- `crypt2pay.crt` is the certificate file of the (net) HSM
- `crypt2pay_client.key` and `crypt2pay_client.crt` are the client certificate and key for the HSM

The log file and log level are specified in the `crypt2pay.rc` files.
To view the logs use the command `tail -f /var/log/crypt2pay.log`

To verify the configuration:

```bash
> nethsmstatus
Read Crypt2pay Config from file: /etc/crypt2pay/crypt2pay.rc
TLS server certificate: /etc/crypt2pay/crypt2pay.crt

*******************************
HSM-1 IP address: 193.251.82.208
*******************************
TLS is enabled
manufacturer ID:        Bull Trustway Crypt2pay HSM
library Description:    nethsm PKCS#11 RPC
libraryVersion:         3.17
Token state:            0X40 OPERATIONAL
Extended state:         0X0
MCS Version:            65539
Firmware Version:       162
Flags:                  0X80000007 CRYPT2PAY HR
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
