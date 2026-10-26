# Thales Luna HSM PKCS#11 Loader

## Overview

`luna_pkcs11_loader` provides native integration with **Thales Luna SA Network HSM** in Cosmian KMS.
Luna is a FIPS 140-3 Level 3 certified hardware security module offering high-assurance cryptography
for enterprise key management and secure operations.

## Features

- **PKCS#11 Integration:** Standard cryptoki interface for all HSM operations
- **FIPS 140-3 Certified:** Level 3 hardware security module
- **Symmetric Cryptography:** AES-128/192/256 (ECB, CBC, CTR modes)
- **Asymmetric Cryptography:** RSA, ECDSA, ECDH
- **Lattice-Based Cryptography:** ML-KEM, ML-DSA (with non-FIPS feature flag)
- **Multi-User Access Control:** Partition-based PIN authentication
- **Redundancy:** Automatic failover to secondary HSM appliance
- **Enterprise Networking:** NTLS secure communication channel

## Requirements

### Hardware
- Luna SA 7.x or higher appliance
- Network connectivity (TCP/IP, typically port 5656 for NTLS)
- Local Luna Client v10.9.x installed

### Software
- Linux x86_64 (only officially supported platform)
- Debian 11+ or equivalent
- Luna Client v10.9.3 or later

### Dependencies (Debian)
```bash
sudo apt-get install -y \
    libusb-1.0-0 libusb-1.0-0-dev \
    libssl-dev libssl3 openssl \
    libpcsclite1 libpcsclite-dev \
    libmotif-common libxt6 libice6 libsm6
```

## Installation

1. **Install Luna Client**
   ```bash
   cd /tmp/LunaClient_10.9.3-43_Linux/64
   sudo bash install.sh
   ```

2. **Verify Luna Installation**
   ```bash
   vtl verify
   # Output: Lists available slots, including your partition slot
   ```

3. **Configure Cosmian KMS**
   ```toml
   [hsm]
   hsm_model = "luna"
   hsm_slot = [5]           # Your assigned slot
   hsm_password = ["<PIN>"] # Partition PIN
   ```

4. **Set Environment Variables**
   ```bash
   export LUNA_HOME=/usr/safenet/lunaclient
   export LUNA_PKCS11_LIB=${LUNA_HOME}/lib/libCryptoki2_64.so
   export LD_LIBRARY_PATH=${LUNA_HOME}/lib:${LD_LIBRARY_PATH}
   ```

## Usage

### Generate AES Key on Luna
```bash
ckms key generate --hsm-slot 5 \
    --key-name "aes-prod" \
    --key-type symmetric \
    --key-length 256
```

### Generate RSA Key on Luna
```bash
ckms key generate --hsm-slot 5 \
    --key-name "rsa-prod" \
    --key-type rsa \
    --key-length 2048
```

### Encrypt/Decrypt
```bash
# Encryption
ckms encrypt --key-name "aes-prod" < plaintext.txt > ciphertext.bin

# Decryption
ckms decrypt --key-name "aes-prod" < ciphertext.bin > plaintext.txt
```

### Sign/Verify
```bash
# Signing
ckms sign --key-name "rsa-prod" < data.txt > signature.bin

# Verification
ckms verify --key-name "rsa-prod" --signature signature.bin < data.txt
```

## Configuration Details

### Chrystoki.conf
The primary Luna configuration file located at `/usr/safenet/lunaclient/conf/Chrystoki.conf`
must specify:
- **HSM appliance IP and port**
- **NTLS server certificate path**
- **NTLS client certificate and private key paths**

Example (one Luna appliance; the Luna Client installs under `/usr/safenet/lunaclient`):
```ini
Chrystoki2 = {
   LibUNIX64 = /usr/safenet/lunaclient/lib/libCryptoki2_64.so;
}

LunaSA Client = {
   SSLConfigFile = /usr/safenet/lunaclient/bin/openssl.cnf;
   ServerCAFile = /usr/safenet/lunaclient/cert/server/<luna-ip>.pem;
   ClientCertFile = /usr/safenet/lunaclient/cert/client/ClientNameCert.pem;
   ClientPrivKeyFile = /usr/safenet/lunaclient/cert/client/ClientNameKey.pem;
   NetClient = 1;
   ServerName00 = <luna-ip>;
   ServerPort00 = 5656;
}

Secure Trusted Channel = {
   ClientTokenLib = /usr/safenet/lunaclient/lib/libSoftToken.so;
   SoftTokenDir = /usr/safenet/lunaclient/configData/token;
   ClientIdentitiesDir = /usr/safenet/lunaclient/data/client_identities;
   PartitionIdentitiesDir = /usr/safenet/lunaclient/data/partition_identities;
}
```

### Environment Variables
| Variable | Default | Purpose |
|----------|---------|---------|
| `LUNA_PKCS11_LIB` | `/usr/safenet/lunaclient/lib/libCryptoki2_64.so` | Luna PKCS#11 library path |
| `LUNA_HOME` | (unset) | Luna client installation directory |
| `LUNACM_CONF` | (unset) | Luna command-line utilities config |
| `ChrystokiConfigurationPath` | `/etc` | Directory containing the `Chrystoki.conf` to use |

## Capabilities

| Capability | Luna Value |
|------------|-----------|
| Max CBC data size | Unlimited (None) |
| Max object enumeration | 256 objects |
| Slot-based multi-tenancy | Yes (multiple partitions) |
| Redundant failover | Yes (primary + secondary) |
| PIN-based authentication | Yes |
| Logging | Real-time PKCS#11 operation logging |

## Troubleshooting

### "Cannot open shared object file"
**Cause:** Luna PKCS#11 library not found
```bash
# Verify installation
ls -l /usr/safenet/lunaclient/lib/libCryptoki2_64.so
# Set LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/usr/safenet/lunaclient/lib:$LD_LIBRARY_PATH
```

### "No HSM slots available"
**Cause:** Network connectivity or NTLS configuration issue
```bash
# Test connectivity
nc -zv <luna-ip> 5656
# Test Luna client
lunacm
# (In lunacm): slot list
```

### "HSM PIN incorrect"
**Cause:** Partition PIN mismatch
```bash
# Verify correct slot number
vtl verify
# Test PIN interactively
lunacm
# (In lunacm): partition list
```

## Testing

Run integration tests (requires Luna client installed):
```bash
cargo test --features luna -- --nocapture
```

## References

- **Luna SA Official Documentation:** https://thalesdocs.com/luna/7.9/NetworkHSM/Content/Home.htm
- **PKCS#11 Specification:** http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/
- **Cosmian KMS HSM Integration:** `documentation/docs/hsm_support/luna.md`

## License

Copyright 2024 Cosmian Tech SAS — see LICENSE file
