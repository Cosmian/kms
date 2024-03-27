The Cosmian KMS can provision secrets to open
[Linux LUKS](https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup) encrypted partitions.

### Documentation

- [systemd-cryptenroll](https://man.linuxreviews.org/man1/systemd-cryptenroll.1.html)
- [Crypttab](https://man.linuxreviews.org/man5/crypttab.5.html)
-
- [p11-kit](https://p11-glue.github.io/p11-glue/p11-kit.html)
- [Red Hat PKCS#11](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/configuring-applications-to-use-cryptographic-hardware-through-pkcs-11_security-hardening)

### Creating a LUKS partition

Using `parted`, determine or create a partition on the disk that you want to encrypt.
In this example, we will use `/dev/vda` as the disk to encrypt.

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

We are going to encrypt the free space at the end.

1. Create a 4th partition from that free space.

```bash
(parted) mkpart 4 102GB 103GB
```

2. Create a LUKS partition on the new partition.
   Enter a password to protect the partition when prompted.

```bash
sudo cryptsetup luksFormat /dev/vda4
```

3. Open the LUKS partition and map it to a device `/dev/mapper/luks`.
   Enter the password when prompted.

```bash
sudo cryptsetup luksOpen /dev/vda4 luks
```

4. Format the mapped device with a filesystem of your choice.

```bash
sudo mkfs.ext4 /dev/mapper/luks
```

5. Mount the encrypted partition.

```bash
sudo mkdir /mnt/luks
sudo mount /dev/mapper/luks /mnt/luks
```

### Installing p11-kit and the Cosmian KMS PKCS#11 module

The Cosmian KMS provides a PKCS#11 module that can be used to access the KMS from applications that
support PKCS#11,
using the `p11-kit` framework. Unfortunately, the support for p11-kit in Ubuntu 20.04 is not
complete,
and the `systemd-cryptenroll` command does not work with `p11-kit`.

The setup works fine for Ubuntu 23.10

The `p11-kit` package provides a way to configure the PKCS#11 module for use by applications.

1. Install the `p11-kit` package.

```bash
sudo apt install p11-kit
```

1. Create the PKCS#11 configuration and module directories

```bash
sudo mkdir -p /etc/pkcs11/modules
```

1. Create a configuration file for the PKCS#11 module.

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

1. Copy the PKCS#11 module to the pkcs11 directory.

```bash
sudo cp libckms-pkcs11.so /etc/pkcs11
```

1. Create a configuration file for the ckms PKCS#11 module.

```bash
sudo tee /etc/pkcs11/modules/ckms_pkcs11.module <<EOF
# Cosmian KMS PKCS#11 module
module: /etc/pkcs11/libckms-pkcs11.so
EOF
```

1. Check that the module loads correctly.

```bash
p11-kit list-modules
```

### Enroll

1. Enroll the LUKS partition with the Cosmian KMS.

```bash
sudo systemd-cryptenroll /dev/vda4 --pkcs11--token-uri=list
```

NOT SUPPORTED ON UBUNTU 22:04 WITH P11-KIT
see: https://bugs.launchpad.net/ubuntu/+source/systemd/+bug/1983758

### FIDO

SoftFido: https://github.com/ellerh/softfido?tab=readme-ov-file
WebAUthM: https://blog.hansenpartnership.com/webauthn-in-linux-with-a-tpm-via-the-hid-gadget/
