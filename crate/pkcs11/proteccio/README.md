<h1>Proteccio HSM wrapper</h1>

This is a wrapper for the Proteccio HSM library. It is written in C++ and provides a simple interface to the Proteccio
HSM library.

## Installation

The library is installed at `/lib/libnethsm.so`

The configuration file is at `/etc/proteccio/proteccio.rc`
The log file and log level are specified in this file.

to view the logs use the command `tail -f /var/log/proteccio.log`

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