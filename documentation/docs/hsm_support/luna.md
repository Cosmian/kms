# Thales Luna HSM

The Thales Luna SA HSM client (v10.9.3) is supported on **Linux (x86_64, Debian/Ubuntu)**.

This guide covers installation, configuration, and verification of PKCS#11 communication with Thales Luna SA appliances.

## System Requirements

### Hardware

- **Architecture:** x86_64 (64-bit Linux)
- **Network:** TCP connectivity to Luna SA servers (port 5656)

### Operating System

- **Linux:** Debian 13 (trixie) or Ubuntu 22.04 LTS or later
- **Kernel:** 6.0+

## Installation

!!! tip "Scripted installation"
    `.github/reusable_scripts/prepare_luna.sh` performs the installation, certificate and configuration
    steps below in one run, on a host or in a container image. See the
    [Luna quick reference](luna_quick_reference.md). The steps below are the manual equivalent.

### Step 1: Install Debian Dependencies

Luna requires several system libraries for USB, SSL, and PKSC#11 support:

```bash
sudo apt-get update
sudo apt-get install -y \
  libusb-1.0-0 libusb-1.0-0-dev \
  libssl-dev libssl3 \
  openssl \
  libpcsclite1 libpcsclite-dev \
  libmotif-common libxt6 libice6 libsm6 \
  alien rpm build-essential
```

The `alien` tool converts Luna RPMs to Debian packages.

### Step 2: Prepare Luna Client Packages

Luna client RPMs should be located in a directory (e.g., `/home/user/LunaClient_10.9.3-43_Linux/64/`).

List available packages:

```bash
ls -lah /path/to/LunaClient_*/64/*.rpm | grep -E "libcryptoki|lunacm|lunacmu|vtl|libshim|softtoken"
```

Expected core packages:

- `libcryptoki-10.9.3-43.x86_64.rpm` — PKCS#11 cryptographic library
- `lunacm-10.9.3-43.x86_64.rpm` — Luna Client Manager
- `lunacmu-10.9.3-43.x86_64.rpm` — Luna CMU utility
- `vtl-10.9.3-43.x86_64.rpm` — Verify Tool (diagnostics)
- `libshim-10.9.3-43.x86_64.rpm` — Luna shim library
- `safenet-softtoken_client-10.9.3-43.x86_64.rpm` — Soft token support

### Step 3: Install Luna Packages via Alien

Convert and install each core package:

```bash
cd /path/to/LunaClient_*/64/

# Core PKCS#11 library
sudo alien -i libcryptoki-10.9.3-43.x86_64.rpm

# Management utilities
sudo alien -i lunacm-10.9.3-43.x86_64.rpm
sudo alien -i lunacmu-10.9.3-43.x86_64.rpm

# Verification tool
sudo alien -i vtl-10.9.3-43.x86_64.rpm

# Shim and soft token support
sudo alien -i libshim-10.9.3-43.x86_64.rpm
sudo alien -i safenet-softtoken_client-10.9.3-43.x86_64.rpm
```

Verify installation:

```bash
dpkg -l | grep -E "libcryptoki|lunacm|lunacmu|vtl|libshim|safenet-softtoken"
```

Expected output (all should show `ii` status):

```text
ii  libcryptoki                     10.9.3-44  amd64  Luna PKCS#11 library
ii  lunacm                          10.9.3-44  amd64  Luna Client Manager
ii  lunacmu                         10.9.3-44  amd64  Luna CMU utility
ii  vtl                             10.9.3-44  amd64  Luna Verify Tool
ii  libshim                         10.9.3-44  amd64  Luna shim library
ii  safenet-softtoken-client        10.9.3-44  amd64  Luna soft token
```

## Configuration

### Step 1: Set Up HSM User and Group

Luna requires a dedicated user group:

```bash
sudo groupadd -f hsmusers
sudo usermod -a -G hsmusers $USER
```

Refresh group membership:

```bash
newgrp hsmusers
```

### Step 2: Deploy Configuration Files

Luna configuration files are typically pre-configured by the HSM administrator. Copy them to the system configuration directory:

```bash
# Assume pre-configured files are in:
# /home/user/Config_Lunaclient/

sudo mkdir -p /etc/luna/conf
sudo cp -r /home/user/Config_Lunaclient_*/* /etc/luna/conf/
sudo chown -R root:hsmusers /etc/luna/conf
sudo chmod 755 /etc/luna/conf
```

Create a system-wide symlink for Chrystoki.conf (Luna's standard location):

```bash
sudo ln -sf /etc/luna/conf/Chrystoki.conf /etc/Chrystoki.conf
```

### Step 3: Create Compatibility Symlink

Luna libraries are installed in `/usr/safenet/`, but configuration expects `/opt/safenet/`:

```bash
sudo mkdir -p /opt/safenet
sudo ln -sf /usr/safenet/lunaclient /opt/safenet/lunaclient
```

### Step 4: Set Up PKCS#11 Library Symlink

Luna installs the 64-bit PKCS#11 library as `libCryptoki2_64.so`. Create a compatibility symlink:

```bash
cd /usr/safenet/lunaclient/lib
sudo ln -sf libCryptoki2_64.so libCryptoki2.so
```

### Step 5: Fix Directory Permissions

Ensure the HSM user can access Luna directories:

```bash
sudo chown -R $USER:hsmusers /opt/safenet/lunaclient
sudo chmod -R 755 /opt/safenet/lunaclient/
sudo chmod 750 /opt/safenet/lunaclient/cert/client  # Private key storage
```

## Network Configuration

### Step 1: Verify HSM Server Reachability

Test connectivity to the Luna SA servers (default port 5656):

```bash
nc -zv <luna-1-ip> 5656
nc -zv <luna-2-ip> 5656
```

Expected output:

```text
Connection to <luna-1-ip> 5656 port [tcp/*] succeeded!
Connection to <luna-2-ip> 5656 port [tcp/*] succeeded!
```

### Step 2: Review Chrystoki.conf Network Settings

Check the configured HSM servers:

```bash
grep -A 20 "LunaSA Client" /etc/luna/conf/Chrystoki.conf | grep -E "ServerName|ServerPort"
```

Expected output (or similar):

```text
   ServerName00 = <luna-1-ip>;
   ServerPort00 = 5656;
   ServerName01 = <luna-2-ip>;
   ServerPort01 = 5656;
```

## Certificate Setup

### Step 1: Deploy Server Certificates

Server certificates authenticate the HSM appliances. Copy them from the pre-configured directory:

```bash
mkdir -p /opt/safenet/lunaclient/cert/server
cp /etc/luna/conf/cert/server/*.pem /opt/safenet/lunaclient/cert/server/
sudo chown -R $USER:hsmusers /opt/safenet/lunaclient/cert/server
```

Verify:

```bash
ls -lah /opt/safenet/lunaclient/cert/server/
```

Expected files:

- `CAFile.pem` — Root CA certificate
- `<luna-1-ip>.pem`, `<luna-1-ip>Cert.pem` — Primary HSM certificates
- `<luna-2-ip>.pem`, `<luna-2-ip>Cert.pem` — Secondary HSM certificates

### Step 2: Generate Client Certificates

Luna uses NTLS (NetLuna TLS) for mutual authentication. Generate client certificates using the VTL tool:

```bash
export LUNA_HOME=/etc/luna/conf
export LD_LIBRARY_PATH=/usr/safenet/lunaclient/lib

mkdir -p /opt/safenet/lunaclient/cert/client

# Generate client certificate (replace '<client-name>' with your hostname/client name)
/usr/safenet/lunaclient/bin/vtl createCert -n <client-name>
```

Expected output:

```text
Private Key created and written to: /opt/safenet/lunaclient/cert/client/<client-name>Key.pem
Certificate created and written to: /opt/safenet/lunaclient/cert/client/<client-name>.pem
```

### Step 3: Create Configuration Symlinks

Chrystoki.conf expects files named `ClientNameCert.pem` and `ClientNameKey.pem`:

```bash
cd /opt/safenet/lunaclient/cert/client
ln -sf <client-name>.pem ClientNameCert.pem
ln -sf <client-name>Key.pem ClientNameKey.pem

# Restrict private key access
chmod 600 <client-name>Key.pem ClientNameKey.pem

ls -lah
```

### Step 4: Deploy Partition Identities

The HSM administrator provides partition identity files (.pid) that establish trust. Copy them:

```bash
cp -r /etc/luna/conf/data/* /opt/safenet/lunaclient/data/
cp -r /etc/luna/conf/configData/* /opt/safenet/lunaclient/configData/

sudo chown -R $USER:hsmusers /opt/safenet/lunaclient/data /opt/safenet/lunaclient/configData
chmod -R 755 /opt/safenet/lunaclient/data
chmod -R 755 /opt/safenet/lunaclient/configData
```

## Environment

No environment variable is required: the Luna tools (`vtl`, `lunacm`) and `libCryptoki2_64.so` read
`/etc/Chrystoki.conf`, or the `Chrystoki.conf` of the directory set in `ChrystokiConfigurationPath`.

## Verification

### Step 1: Verify PKCS#11 Library

Check that the library loads successfully:

```bash
ldd /usr/safenet/lunaclient/lib/libCryptoki2_64.so | grep -E "not found|error"
```

Expected output: No missing dependencies.

### Step 2: List HSM Slots

Use the VTL verify command to enumerate available partitions:

```bash
/usr/safenet/lunaclient/bin/vtl verify
```

Expected output (example):

```text
The following Luna SA Slots/Partitions were found:

Slot Serial #         Label
==== ================ =====
   0    <partition-serial>  Sandbox
   1    <partition-serial>  QA
   2    <partition-serial>  Other
```

### Step 3: Detailed Slot Information

Get full hardware details:

```bash
echo "slot list" | /usr/safenet/lunaclient/bin/lunacm
```

Expected output (partial):

```text
Available HSMs:
Slot Id ->              0
Label ->                Sandbox
Serial Number ->        <partition-serial>
Model ->                LunaSA
Firmware Version ->     7.9.1
Bootloader Version ->   1.1.5
Configuration ->        Luna User Partition With SO (PED) Key Export With Cloning Mode
```

### Step 4: Run Diagnostics

Collect full diagnostic information:

```bash
/usr/safenet/lunaclient/bin/vtl supportInfo

# Read the generated report
cat c_supportInfo.txt | grep -E "CLIENT FILE CHECKS|Certificate|SSL|PING"
```

Check that all certificate paths resolve and network connectivity is confirmed.

### Step 5: Check Partition Activation (No Login)

A KMS needs an activated partition. Check it without logging in, to avoid consuming failed-login
attempts:

```bash
printf 'slot set -slot 0\npartition showinfo\nrole show -name co\nexit\n' \
  | /usr/safenet/lunaclient/bin/lunacm | grep -E "Partition Label|Object Count|Activated"
```

The Crypto Officer role must report `Activated.`.

## KMS Configuration

The KMS loads the Luna PKCS#11 library natively with `hsm_model = "luna"`.

!!! note "See Also"
    Refer to [HSM Operations](hsm_operations.md) for detailed KMS HSM integration steps.

### Configuration via TOML File

```toml
hsm_model    = "luna"
hsm_admin    = ["admin"]                 # KMS users with admin rights on the HSM
hsm_slot     = [0]                       # Slot index from `vtl verify`
hsm_password = ["<partition-password>"]  # Crypto Officer password of the partition
```

### Configuration via Command Line

```bash
# KMS_HSM_PASSWORD keeps the password out of `ps` output
KMS_HSM_PASSWORD='<partition-password>' ./cosmian_kms \
  --hsm-model luna \
  --hsm-admin admin \
  --hsm-slot 0
```

### Luna-specific behavior

- **Library**: `/usr/safenet/lunaclient/lib/libCryptoki2_64.so` by default; override it with the
  `LUNA_PKCS11_LIB` environment variable. Luna is supported on Linux x86_64 only.
- **Several Luna appliances**: keep one `Chrystoki.conf` per appliance and point the KMS process
  to the directory of the one to use with `ChrystokiConfigurationPath=<directory>`.
- **Sensitive keys**: Luna rejects an explicit `CKA_SENSITIVE=false` with
  `CKR_ATTRIBUTE_VALUE_INVALID`. The KMS therefore omits `CKA_SENSITIVE` on Luna and sets only
  `CKA_EXTRACTABLE`: a key created without `--sensitive` gets `CKA_EXTRACTABLE=true` (it can be
  wrapped) and Luna's default `CKA_SENSITIVE` value.
- **AES-GCM**: the KMS uses classic `C_EncryptInit` AES-GCM (the PKCS#11 3.0 message API fails on
  Luna). In FIPS mode Luna generates the IV and appends it to the output; the KMS uses that IV with
  firmware 7.9.3 or later (96-bit IV) and rejects the 16-byte IV of older firmware.
- **Login lockout**: the partition locks after *Max failed user logins allowed* (10 by default)
  wrong passwords. Check the password before starting the KMS repeatedly.
- **Verified on**: Luna Network HSM 7, firmware 7.8.5 and 7.9.1, Luna Client 10.9.3.

## Kubernetes (Helm chart)

Recommended setup: the **official KMS image, unmodified**, with the Thales Luna Client runtime
copied by an init container from a small client image, and the Luna configuration and credentials
mounted from Kubernetes Secrets. The KMS image is upgraded by changing its tag, the Luna Client is
versioned independently, no image holds a secret, and the chart's default hardening (UID 1000,
read-only root filesystem) is kept. The KMS image ships the C++ runtime required by
`libCryptoki2_64.so` (`/usr/local/cosmian/lib/hsm`, on `LD_LIBRARY_PATH`).

!!! note "KMS version"
    `hsm_model = "luna"` and the C++ runtime in the image are available in KMS releases after
    5.28.0. KMS 5.28.0 and earlier images reject `luna` and cannot load `libCryptoki2_64.so`.

To log the Luna PKCS#11 calls in Kubernetes, mount a writable `emptyDir` for the log files and
follow [Logging and Diagnostics](#logging-and-diagnostics); the root filesystem is read-only.

### 1. Luna Client image

The Thales Luna Client is proprietary and is not part of the KMS image: build this image once per
Luna Client version, from the Thales tarball (`LunaClient.tar`) and
`.github/reusable_scripts/prepare_luna.sh` (without `LUNA_CONFIG`, it installs the client runtime only).

```dockerfile
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends rpm2cpio cpio \
    && rm -rf /var/lib/apt/lists/*
COPY LunaClient.tar prepare_luna.sh /tmp/
RUN LUNA_CLIENT_TAR=/tmp/LunaClient.tar bash /tmp/prepare_luna.sh

FROM debian:bookworm-slim
COPY --from=build /usr/safenet/lunaclient/lib /usr/safenet/lunaclient/lib
COPY --from=build /usr/safenet/lunaclient/bin /usr/safenet/lunaclient/bin
```

### 2. Luna configuration in Secrets

`Chrystoki.conf`, mounted with the other files under `/etc/luna`:

```text
Chrystoki2 = {
   LibUNIX64 = /usr/safenet/lunaclient/lib/libCryptoki2_64.so;
}

LunaSA Client = {
   SSLConfigFile = /usr/safenet/lunaclient/bin/openssl.cnf;
   ServerCAFile = /etc/luna/cert/server.pem;
   ClientCertFile = /etc/luna/cert/client.pem;
   ClientPrivKeyFile = /etc/luna/cert/client-key.pem;
   NetClient = 1;
   ServerName00 = <luna-ip>;
   ServerPort00 = 5656;
}

Secure Trusted Channel = {
   ClientTokenLib = /usr/safenet/lunaclient/lib/libSoftToken.so;
   SoftTokenDir = /etc/luna/token;
   ClientIdentitiesDir = /etc/luna/client_identities;
   PartitionIdentitiesDir = /etc/luna/partition_identities;
}
```

```bash
kubectl -n kms create secret generic luna-files \
  --from-file=Chrystoki.conf \
  --from-file=server.pem=cert/server/<luna-ip>.pem \
  --from-file=client.pem=<client-name>.pem \
  --from-file=client-key.pem=<client-name>Key.pem \
  --from-file=token_v2.db=configData/token/001/token_v2.db \
  --from-file=clientRD=data/client_identities/clientRD \
  --from-file=data/partition_identities/   # one key per <partition-serial>.pid
kubectl -n kms create secret generic luna-password --from-literal=password='<partition-password>'
```

### 3. Helm values

```yaml
image:
  repository: ghcr.io/cosmian/kms
  tag: <version>
extraArgs: [--hsm-model, luna, --hsm-slot, "0", --hsm-admin, admin]
extraEnv:
  - name: ChrystokiConfigurationPath
    value: /etc/luna
  - name: KMS_HSM_PASSWORD
    valueFrom:
      secretKeyRef: {name: luna-password, key: password}
initContainers:
  - name: luna-client
    image: <registry>/luna-client:<luna-client-version>
    command: [cp, -r, /usr/safenet/lunaclient/lib, /usr/safenet/lunaclient/bin, /luna-client/]
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
    volumeMounts:
      - {name: luna-client, mountPath: /luna-client}
extraVolumes:
  - name: luna-client
    emptyDir: {}
  - name: luna
    secret:
      secretName: luna-files
      defaultMode: 0440
      items:
        - {key: Chrystoki.conf, path: Chrystoki.conf}
        - {key: server.pem, path: cert/server.pem}
        - {key: client.pem, path: cert/client.pem}
        - {key: client-key.pem, path: cert/client-key.pem}
        - {key: token_v2.db, path: token/001/token_v2.db}
        - {key: clientRD, path: client_identities/clientRD}
        - {key: <partition-serial>.pid, path: partition_identities/<partition-serial>.pid}
extraVolumeMounts:
  - name: luna-client
    mountPath: /usr/safenet/lunaclient
    readOnly: true
  - name: luna
    mountPath: /etc/luna
    readOnly: true
```

Add one `items` entry per partition identity file. On minikube with a Luna Network HSM 7 (firmware
7.9.1) and the chart's default security context, HSM key creation, AES-GCM encryption/decryption and
ECDSA signature were validated through the KMS pod with the Luna Client runtime inside the image; with
this init-container setup, the official image loading and initializing the Luna library was validated.

## Logging and Diagnostics

Thales `cklog` logs every PKCS#11 call. Install `libcklog2.so` from the `cklog` RPM of the Luna
Client tarball (`prepare_luna.sh` does not install it), then point the KMS to it and `CkLog2` to the
real library. The KMS loads `LUNA_PKCS11_LIB` directly and does not use `Chrystoki2.LibUNIX64`:

```bash
LUNA_PKCS11_LIB=/usr/safenet/lunaclient/lib/libcklog2.so
```

Add to `Chrystoki.conf` (the log directory must be writable by the KMS user):

```text
CkLog2 = {
   LibUNIX64 = /usr/safenet/lunaclient/lib/libCryptoki2_64.so;
   Enabled = 1;
   File = /var/log/luna/cklog.txt;
   Error = /var/log/luna/error.txt;
   NewFormat = 1;
   LoggingMask = ALL_FUNC;
}
```

Each call is logged with its return code and duration, e.g.
`STRTGetFunctionList {}` then `FINIGetFunctionList CKR_OK(83ms) {}`. Every call is written to the
log file: enable it for diagnostics only.

## References

- [Thales Luna HSM Documentation](https://thalesdocs.com/luna/7.9/NetworkHSM/Content/Home.htm)
- [PKCS#11 Standard (RSA Labs)](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/)
- [Eviden KMS HSM Integration](hsm_operations.md)

## Luna Network HSM Deployment (Complete Example)

This section documents a complete, end-to-end deployment of Cosmian KMS with Thales Luna Network HSM 7 (v7.8.5).

### Scenario

- **KMS Server:** `<kms-host>`
- **Luna HSM:** `<luna-ip>` (Luna Network HSM 7, v7.8.5)
- **Luna Client:** v10.9.3
- **HSM Partition:** slot 0
- **HSM Password:** `<partition-password>` (from the HSM administrator)

### Deployment Steps

#### 1. Pre-configuration Files

The Luna administrator provides pre-configured files, here in `/path/to/luna_config/`:

```bash
/path/to/luna_config/
├── Chrystoki.conf
├── cert/server/
│   ├── <luna-ip>.pem            # Server certificate
│   ├── <luna-ip>Cert.pem
│   └── CAFile.pem
├── configData/token/001/
│   └── token_v2.db              # STC soft token database
└── data/
    ├── client_identities/
    │   └── clientLuna7RD        # Luna Network HSM specific identity
    └── partition_identities/
        └── *.pid                # Partition identities
```

#### 2. Deploy to /usr/safenet/lunaclient/

**Important:** Luna Network HSM uses `/usr/safenet/lunaclient/` (NOT `/opt/safenet/`).

```bash
# Create directory structure
sudo mkdir -p /usr/safenet/lunaclient/{cert/server,data/{client_identities,partition_identities},configData/token/001}

# Copy server certificate (rename to lunasa7rd.pem for Luna Network HSM)
sudo cp /path/to/luna_config/cert/server/<luna-ip>.pem \
  /usr/safenet/lunaclient/cert/server/lunasa7rd.pem

# Copy STC token database (rename with .LUNA7 suffix)
sudo cp /path/to/luna_config/configData/token/001/token_v2.db \
  /usr/safenet/lunaclient/configData/token/001/token_v2.db.LUNA7

# Copy Luna Network HSM specific client identity
sudo cp /path/to/luna_config/data/client_identities/clientLuna7RD \
  /usr/safenet/lunaclient/data/client_identities/

# Copy all partition identities
sudo cp /path/to/luna_config/data/partition_identities/*.pid \
  /usr/safenet/lunaclient/data/partition_identities/
```

#### 3. Set Correct Permissions

```bash
# All files owned by hsmusers group
sudo chown -R :hsmusers /usr/safenet/lunaclient

# File permissions (rw-r--r--)
sudo chmod 644 /usr/safenet/lunaclient/cert/server/lunasa7rd.pem
sudo chmod 644 /usr/safenet/lunaclient/configData/token/001/token_v2.db*
sudo chmod 644 /usr/safenet/lunaclient/data/client_identities/clientLuna7RD
sudo chmod 644 /usr/safenet/lunaclient/data/partition_identities/*.pid

# Directory permissions
sudo chmod -R 755 /usr/safenet/lunaclient
```

#### 4. Configure Chrystoki.conf for Luna Network HSM

**Key differences for Luna Network HSM:**

- `ServerCAFile`: Use `lunasa7rd.pem` (not individual IP-based certs)
- Remove `ClientCertFile` and `ClientPrivKeyFile` entries
- Use `/usr/safenet/` paths (not `/opt/safenet/`)
- Include `ClientTokenLib` for STC soft tokens

```bash
cat | sudo tee /etc/Chrystoki.conf << 'EOF'
Chrystoki2 = {
   LibUNIX64 = /usr/safenet/lunaclient/lib/libCryptoki2_64.so;
}

Luna = {
  DefaultTimeOut = 500000;
  PEDTimeout1 = 100000;
  PEDTimeout2 = 200000;
  PEDTimeout3 = 20000;
  KeypairGenTimeOut = 2700000;
  CloningCommandTimeOut = 300000;
  CommandTimeOutPedSet = 720000;
}

LunaSA Client = {
   ReceiveTimeout = 20000;
   SSLConfigFile = /usr/safenet/lunaclient/bin/openssl.cnf;
   ServerCAFile = /usr/safenet/lunaclient/cert/server/lunasa7rd.pem;
   NetClient = 1;
   TCPKeepAlive = 1;
   ServerName00 = <luna-ip>;
   ServerPort00 = 5656;
}

Secure Trusted Channel = {
   ClientTokenLib = /usr/safenet/lunaclient/lib/libSoftToken.so;
   SoftTokenDir = /usr/safenet/lunaclient/configData/token;
   ClientIdentitiesDir = /usr/safenet/lunaclient/data/client_identities;
   PartitionIdentitiesDir = /usr/safenet/lunaclient/data/partition_identities;
}
EOF
```

#### 5. Configure KMS with HSM Backend

In `/etc/cosmian_kms/config.toml`:

```toml
hsm_model    = "luna"
hsm_admin    = ["*"]
hsm_slot     = [0]
hsm_password = ["<partition-password>"]
```

#### 6. Verify Installation

```bash
export LUNA_HOME=/usr/safenet/lunaclient
export PATH=/usr/safenet/lunaclient/bin:${PATH}

# Should show all partitions of the appliance (slot 0 included)
/usr/safenet/lunaclient/bin/vtl verify
```

### Troubleshooting

**Issue:** `vtl verify` shows no partitions

**Solution:** Check that partition identities are in the correct location:

```bash
ls -la /usr/safenet/lunaclient/data/partition_identities/
# Should show one <partition-serial>.pid file per partition
```

**Issue:** PKCS#11 login hangs

**Solution:** HSM administrator must enable partition challenge authentication:

```bash
# On Luna appliance (admin user)
lunash:> partition activateChallenge -partition <partition-label> -challenge <partition-password>
```

After activation, restart KMS and key creation will succeed.

### Symlink Note

If your system has `/opt/safenet/lunaclient` as a symlink to `/usr/safenet/lunaclient`, both paths work interchangeably. Ensure Chrystoki.conf uses `/usr/safenet/` paths explicitly.
