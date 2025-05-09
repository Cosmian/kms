# LUKS

The Cosmian KMS can provision secrets to open
[Linux LUKS](https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup) encrypted partitions. The
secret never leaves the KMS and can be used to unlock the partition at boot time.

## Installing p11-kit and the Cosmian KMS PKCS#11 module

The Cosmian KMS provides a PKCS#11 module that can be used to access the KMS from applications that
support PKCS#11, using the `p11-kit` framework.

With LUKS, the system provided `systemd-cryptenroll` command
must have support for `p11-kit` which you can check by running `systemd-cryptenroll --help` and
checking for the `+P11KIT` flag.

```bash
❯ systemd-cryptenroll --version

systemd 253 (253.5-1ubuntu6.1)
+PAM +AUDIT +SELINUX +APPARMOR +IMA +SMACK +SECCOMP +GCRYPT -GNUTLS +OPENSSL +ACL +BLKID +CURL
+ELFUTILS +FIDO2 +IDN2 -IDN +IPTC +KMOD +LIBCRYPTSETUP +LIBFDISK +PCRE2 -PWQUALITY
+P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD -BPF_FRAMEWORK -XKBCOMMON +UTMP +SYSVINIT
default-hierarchy=unified
```

Unfortunately, Ubuntu 22.04 does not provide p11-kit support, however the setup works fine for
Ubuntu 24.04.

### 1. Install the `p11-kit` package

#### Ubuntu 24.04

```bash
sudo apt install p11-kit cryptsetup
```

#### Rocky Linux 9

```bash
sudo dnf install p11-kit cryptsetup
```

### 2. Create the PKCS#11 configuration and module directories

```bash
sudo mkdir -p /etc/pkcs11/modules
```

### 3. Create a configuration file for the PKCS#11 module

```bash
sudo tee /etc/pkcs11/pkcs11.conf <<EOF
# This setting controls whether to load user configuration from the
# ~/.config/pkcs11 directory. Possible values:
#    none: No user configuration
#    merge: Merge the user config over the system configuration (default)
#    only: Only user configuration, ignore system configuration
user-config: merge
EOF
```

### 4. Copy the PKCS#11 module to the pkcs11 directory

```bash
sudo cp libcosmian_pkcs11.so /usr/local/lib/
```

### 5. Create a configuration file for the cosmian PKCS#11 module

```bash
sudo tee /etc/pkcs11/modules/cosmian_pkcs11.module <<EOF
# Cosmian KMS PKCS#11 module
module: /usr/local/lib/libcosmian_pkcs11.so
EOF
```

### 6. Check that the module loads correctly

```bash
> p11-kit list-modules

...
cosmian_pkcs11: /usr/local/lib/libcosmian_pkcs11.so
 library-description: Cosmian KMS PKCS#11 provider
 library-manufacturer: Cosmian
 library-version: x.y
 token: Cosmian-KMS
     manufacturer: Cosmian
     model: software
     serial-number: x.y.z
     flags:
           rng
           write-protected
           login-required
           user-pin-initialized
           protected-authentication-path
           token-initialized

```

## Configuring the access to the KMS

The PKCS#11 module uses the same configuration file as
the [CLI](../../cosmian_cli/index.md).
Since it may be run as a system user, the configuration file should be made available
in `/etc/cosmian/cosmian.toml`.

See [Authenticating users to the KMS](../authentication.md) to learn
how to configure the KMS to use Open ID connect or certificate authentication.

Here is an example configuration file for the PKCS#11 provider library accessing the KMS using a
PKCS#12 file for authentication.

```toml
[kms_config.http_config]
server_url = "https://kms.acme.com:9999"
ssl_client_pkcs12_path = "./certificates/machine123.acme.p12"
ssl_client_pkcs12_password = "machine123_pkcs12_password"
```

To use Open ID connect, install the [Cosmian CLI](../../cosmian_cli/index.md) from
[Cosmian packages](https://package.cosmian.com/kms/) and
use the `cosmian kms login` command to authenticate to the KMS first.

## Creating an RSA key pair using openssl and importing it into the Cosmian KMS

To generate a self-signed certificate with RSA 2048bit key and in PKCS12 format, you can use the
OpenSSL command-line tool. Here are the steps:

### 1. Generate a new private key

```bash
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
```

### 2. Create a self-signed certificate

```bash
openssl req -new -x509 -key private_key.pem -out cert.pem -days 365
```

### 3. Convert the certificate and private key to PKCS12 format

```bash
openssl pkcs12 -export -out certificate.p12 -inkey private_key.pem -in cert.pem
```

### 4. Import the PKCS12 file into the Cosmian KMS using a `disk-encryption` tag

```bash
cosmian kms certificates import -f pkcs12 -t disk-encryption certificate.p12 disk-encryption

The private key in the PKCS12 file was imported with id: 6fc631...
Tags:
 - disk-encryption
```

A tag different from `disk-encryption` can be used, but it must be set in the
in the `COSMIAN_PKCS11_DISK_ENCRYPTION_TAG` environment variable when enrolling the token (sse
below).

## Creating a LUKS partition

First allocate some space then create a LUKS partition using `cryptsetup`.

### 1. Allocating space for the LUKS partition

LUKS partitions can be created either from disk partitions or from a file.

#### From a file

Use either `dd` or `fallocate` to create a file that will be used as the LUKS partition.

```bash
# Create a 1GB file
fallocate -l 1G /path/to/file
```

Then use `path/to/file` as the device to encrypt.

#### From a disk partition

Using `parted`, determine or create a partition on the disk that you want to encrypt.
In this example, we assume the disk is available as `/dev/vda`.

If needed, use `parted`to resize the last partition and create free space at the end of the disk.

```bash
sudo parted /dev/vda
(parted) print free
Number  Start   End     Size    File system  Name  Flags
        17.4kB  1049kB  1031kB  Free Space
 1      1049kB  1128MB  1127MB  fat32              boot, esp
 2      1128MB  3276MB  2147MB  ext4
 3      3276MB  102GB   98.7GB
        102GB   103GB   1079MB  Free Space
```

Make a 4th partition `/dev/vda4` from the free space at the end.

```bash
(parted) mkpart 4 102GB 103GB
```

### 2. Creating a LUKS 2 partition on the allocated space

Enter a passphrase to protect the partition when prompted.
The encrypted passphrase will be stored in the LUKS header in key slot 0.

```bash
sudo cryptsetup luksFormat --type luks2 --key-slot 0 /dev/vda4
```

or alternatively, if you created a file:

```bash
sudo cryptsetup luksFormat --type luks2 --key-slot 0 /path/to/file
```

Make sure to remember the passphrase, as it will be needed to unlock the partition
during `cryptenroll` or when rotating the RSA keys.

## Enrolling the LUKS partition with the Cosmian KMS

Logging of the PKCS#11 module is controlled by the `COSMIAN_PKCS11_LOGGING_LEVEL` environment variable.
The logging level can be set to `trace`, `debug`, `info`, `warn`, or `error` and defaults to `info`
when not set.

The RSA key pair is searched opn the KMS using a tag controlled by
the `COSMIAN_PKCS11_DISK_ENCRYPTION_TAG` environment variable.
When not set, the default tag searched is `disk-encryption`.

### 1. Enroll the partition with the Cosmian KMS

```bash
# this is equivalent to
# sudo COSMIAN_PKCS11_LOGGING_LEVEL=info COSMIAN_PKCS11_DISK_ENCRYPTION_TAG=disk-encryption systemd-cryptenroll /dev/vda4  --pkcs11-token-uri=pkcs11:token=Cosmian-KMS
> sudo systemd-cryptenroll --pkcs11-token-uri=pkcs11:token=Cosmian-KMS /dev/vda4

🔐 Please enter current passphrase for disk /dev/vda4: *************
cosmian-pkcs11 module logging at INFO level to file /var/log/cosmian-pkcs11.log
Successfully logged into security token 'Cosmian-KMS' via protected authentication path.
New PKCS#11 token enrolled as key slot 1.
```

### 3. Verify the enrollment

```bash
 > sudo cryptsetup luksDump /dev/vda4

LUKS header information
Version:        2
Epoch:          5
...
Keyslots:
  0: luks2
  ....
  1: luks2
     Key:        512 bits
     Priority:   normal
     Cipher:     aes-xts-plain64
     Cipher key: 512 bits
     PBKDF:      pbkdf2
     Hash:       sha512
     ...


Tokens:
  0: systemd-pkcs11
     pkcs11-uri: pkcs11:token=Cosmian-KMS
     pkcs11-key: 0b 94 e0 ...
...
```

### 4. Test attaching the LUKS partition to `/dev/mapper/myluks` using the Cosmian-KMS token in slot 0

 ```bash
 > sudo cryptsetup open --type luks2  --token-id=0 --token-only /dev/vda4 myluks

 cosmian-pkcs11 module logging at INFO level to file /var/log/cosmian-pkcs11.log
 Successfully logged into security token 'Cosmian-KMS' via protected authentication path.
 Successfully decrypted key with security token.
 ```

### 5. Format the LUKS partition (do this only once)

```bash
sudo mkfs.ext4 /dev/mapper/myluks
```

### 6. Mount the partition

```bash
sudo mkdir /mnt/myluks #only once
sudo mount /dev/mapper/myluks /mnt/myluks
```

### 7. Close the LUKS partition

```bash
sudo umount /mnt/myluks
sudo cryptsetup close myluks
```

## Automatically unlocking the LUKS partition at boot

To automatically unlock the LUKS partition at boot, you cannot use the `/etc/crypttab` file
because the network is not available when `systemd-cyptsetup` is run.

You need to create a systemd service that unlocks the LUKS partition at the right time, after the
network is available.

### 1. Create the bash script that unlocks and mounts the partition

```bash
sudo tee -a /root/mount_myluks.sh <<EOF
#!/bin/bash
set -e
set -x
# unlock the partition
cryptsetup open --type luks2  --token-id=0 --token-only /dev/vda4 myluks
# mount the partition
mount /dev/mapper/myluks /mnt/myluks
EOF
```

```bash
sudo chmod +x /root/mount_myluks.sh
```

### 2. Create the systemd service file

```bash
sudo tee -a /etc/systemd/system/mount_myluks.service <<EOF
[Unit]
Description=open and mount the encrypted /dev/vda4 to /mnt/myluks
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash /root/mount_myluks.sh

[Install]
WantedBy=multi-user.target
EOF
```

### 3. Enable the service

```bash
> sudo systemctl enable mount_myluks.service

Created symlink /etc/systemd/system/multi-user.target.wants/mount_myluks.service → /etc/systemd/system/mount_myluks.service.
```

```bash
sudo systemctl daemon-reload
```

### 4. Reboot the machine to test the service

```bash
sudo reboot
```

The LUKS partition should be automatically unlocked and mounted at boot to `/mnt/myluks`.
Check `dmesg`, and `/var/log/cosmian-pkcs11.log` for any errors.

## Rotating the keys

To rotate the keys used to encrypt the LUKS partition, you can generate a new key pair and import it
into the Cosmian KMS.

Then, you can re-enroll the LUKS partition with the new key. You MUST know the passphrase to
perform this operation.

### 1. Wipe the old key from the LUKS partition

```bash
sudo systemd-cryptenroll /dev/vda4  --wipe-slot=pkcs11

Wiped slot 1.
```

### 2. Revoke the old key from the Cosmian KMS

```bash
cosmian kms certificates revoke -k 6fc631...  "revoked"

Successfully revoked: 6fc631....
```

### 3. Follow the steps to generate a new key pair and import it into the Cosmian KMS

### 4. Enroll the LUKS partition with the new key; you will be prompted for the passphrase

## External documentation

- [cryptsetup](https://www.man7.org/linux/man-pages/man8/cryptsetup.8.html)
- [systemd-cryptenroll](https://www.man7.org/linux/man-pages/man1/systemd-cryptenroll.1.html)
- [p11-kit](https://p11-glue.github.io/p11-glue/p11-kit.html)
