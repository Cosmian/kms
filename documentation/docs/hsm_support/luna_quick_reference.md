# Thales Luna HSM Quick Reference

## Installation

`.github/reusable_scripts/prepare_luna.sh` installs the Luna Client runtime (PKCS#11 library, STC soft
token, `vtl`, `lunacm`) and its NTLS configuration on Debian/Ubuntu, on a host or in a container
image. The Thales Luna Client is proprietary: pass the Thales tarball and the files delivered by
the HSM administrator.

```bash
sudo apt-get install -y rpm2cpio cpio unzip

LUNA_CLIENT_TAR=/path/to/610-000397-019_SW_Linux_Luna_Client_V10.9.3_RevA.tar \
LUNA_CONFIG="/path/to/Config All Lunaclient.zip" \
LUNA_CLIENT_CERT=/path/to/<client-name>.pem \
LUNA_CLIENT_KEY=/path/to/<client-name>Key.pem \
LUNA_SERVER=<luna-ip> \
  .github/reusable_scripts/prepare_luna.sh
```

| Variable | Meaning |
| --- | --- |
| `LUNA_CLIENT_TAR` | Thales Luna Client tarball |
| `LUNA_CONFIG` | Administrator configuration (`.zip` or directory with `cert/server/`, `configData/`, `data/`) |
| `LUNA_CLIENT_CERT`, `LUNA_CLIENT_KEY` | Client certificate registered on the appliance, and its key |
| `LUNA_SERVER` | Appliance address |
| `LUNA_SERVER_CERT` | Server certificate in `cert/server/` (default `<LUNA_SERVER>.pem`) |
| `LUNA_ROOT` | Installation directory (default `/usr/safenet/lunaclient`) |
| `LUNA_CONF_DIR` | Directory receiving `Chrystoki.conf` (default `/etc`) |
| `LUNA_OWNER` | User running the KMS, owner of the files (default: invoking user) |
| `LUNA_SKIP_VERIFY` | `1` to skip `vtl verify` (image build without access to the appliance) |

The script ends with `vtl verify`, which lists the partitions visible to this client.

## Client certificate

If the administrator has not issued one, generate it and send `<client-name>.pem` to the
administrator for registration on the appliance:

```bash
/usr/safenet/lunaclient/bin/vtl createCert -n <client-name>
```

## Several appliances

Run `prepare_luna.sh` once per appliance with a different `LUNA_CONF_DIR`, then start each KMS with
`ChrystokiConfigurationPath=<LUNA_CONF_DIR>`.

## KMS Server Configuration

```toml
hsm_model    = "luna"
hsm_admin    = ["admin"]
hsm_slot     = [0]                       # From vtl verify output
hsm_password = ["<partition-password>"]  # Or the KMS_HSM_PASSWORD environment variable
```

HSM keys must be created sensitive (`ckms ... keys create --sensitive`) on partitions where
*Allow private key wrapping* is off.

## Kubernetes and logging

- Kubernetes: official KMS image, Luna Client runtime from an init container, configuration from
  Secrets: see [Kubernetes (Helm chart)](luna.md#kubernetes-helm-chart).
- PKCS#11 call logging with Thales `cklog`: see [Logging and Diagnostics](luna.md#logging-and-diagnostics).

## Verification

```bash
/usr/safenet/lunaclient/bin/vtl verify

# Partition details and activation state, without logging in
printf 'slot set -slot 0\npartition showinfo\nrole show -name co\nexit\n' \
  | /usr/safenet/lunaclient/bin/lunacm

# Network path to the appliance
nc -zv <luna-ip> 5656
```

Avoid repeated logins with an unverified password: the partition locks after
*Max failed user logins allowed* (10 by default).

## Common Issues

| Issue | Solution |
| --- | --- |
| `vtl verify` finds no slot | The client certificate is not registered on the appliance, or no partition is assigned to it: contact the HSM administrator. |
| `CKR_ATTRIBUTE_VALUE_INVALID` on key creation | The KMS predates Luna's `CKA_SENSITIVE` handling: upgrade, or create the key as sensitive (`--sensitive`). |
| `Failed logging in. Return code: 160` | Wrong partition password (`CKR_PIN_INCORRECT`): stop and check it before retrying. |
| Partition not visible | Check `data/partition_identities/` and re-run `vtl verify`. |
| `libstdc++.so.6: cannot open shared object file` (KMS container) | Use a KMS image released after 5.28.0: it ships the C++ runtime required by `libCryptoki2_64.so`. |
| `libSoftToken.so: Permission denied` (non-root KMS user) | Install the client with `prepare_luna.sh`, which makes `lib/` and `bin/` readable by all users. |
| `CKR_TOKEN_NOT_PRESENT` (`0xE0`) at startup or on every operation | The appliance is unreachable: check the network path to port 5656 (`nc -zv <luna-ip> 5656`). |

## References

- [Thales Luna HSM Docs](https://thalesdocs.com/luna/7.9/NetworkHSM/Content/Home.htm)
- [Full Luna Guide](luna.md)
