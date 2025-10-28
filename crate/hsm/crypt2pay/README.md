# Crypt2pay HSM wrapper

This is a wrapper for the Crypt2pay HSM library. It is written in Rust and provides a simple interface to the Crypt2pay
HSM library.

## Installation

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
- The two files with extensions `.kdk` and `.ksk` <- The Crypt2pay key files

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
