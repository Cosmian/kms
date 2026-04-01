# Custom OpenSSL Build

The Cosmian KMS **dynamic** package links against OpenSSL at runtime.
You can redirect the service to a custom OpenSSL build — for example, a
vendor-supplied or hardware-accelerated variant — without touching any
Cosmian-owned files, by overriding the systemd service environment.

!!! warning "Applies to dynamic builds only"
    Static builds embed OpenSSL at compile time and cannot be redirected at
    runtime.

## How it works

The KMS systemd unit (/lib/systemd/system/cosmian_kms.service) sets three environment variables that together control which OpenSSL is loaded:

| Variable          | Default value (package install)          | Purpose                                                           |
| ----------------- | ---------------------------------------- | ----------------------------------------------------------------- |
| `LD_LIBRARY_PATH` | `/usr/local/cosmian/lib`                 | Directory searched first for `libssl.so.3` / `libcrypto.so.3`     |
| `OPENSSL_CONF`    | `/usr/local/cosmian/lib/ssl/openssl.cnf` | OpenSSL configuration file                                        |
| `OPENSSL_MODULES` | `/usr/local/cosmian/lib/ossl-modules`    | Directory containing provider modules (e.g. `fips.so, legacy.so`) |

Pointing all three at your custom OpenSSL installation is sufficient to make
the service use it exclusively.

On startup the server logs the active OpenSSL version:

```text
INFO cosmian_kms: [run] OpenSSL version: OpenSSL 3.X.Y DD Mon YYYY,
     in OPENSSLDIR: "/usr/local/ssl", number: 30X000Y0
```

## Overriding via systemd drop-in

### 1. Install your custom OpenSSL build

Place the libraries and configuration files anywhere on the server, for example
`/opt/openssl-custom/`.  The expected layout is:

```text
/opt/openssl-custom/
  lib/
    libssl.so.3
    libcrypto.so.3
    ossl-modules/
      fips.so
      legacy.so
  ssl/
    openssl.cnf
```

### 2. Create the systemd drop-in override

```bash
sudo systemctl edit cosmian_kms
```

This opens `$EDITOR` with a drop-in template saved at
`/etc/systemd/system/cosmian_kms.service.d/override.conf`.
Add the three environment variables, replacing the paths with those of your
installation:

```ini
[Service]
Environment="LD_LIBRARY_PATH=/opt/openssl-custom/lib"
Environment="OPENSSL_CONF=/opt/openssl-custom/ssl/openssl.cnf"
Environment="OPENSSL_MODULES=/opt/openssl-custom/lib/ossl-modules"
```

### 3. Reload and restart

```bash
sudo systemctl daemon-reload
sudo systemctl restart cosmian_kms
```

### 4. Verify

```bash
sudo journalctl -u cosmian_kms --no-pager | grep "OpenSSL version"
```

The log line should reflect your custom build string.

## Rollback

Remove the drop-in override file and restart the service to revert to the
Cosmian-bundled OpenSSL:

```bash
sudo rm -f /etc/systemd/system/cosmian_kms.service.d/override.conf
sudo systemctl daemon-reload
sudo systemctl restart cosmian_kms
```

## Notes

- **ABI compatibility**: `libssl.so.3` / `libcrypto.so.3` must be
  ABI-compatible with OpenSSL 3.x (major version `3`).
- **Provider modules**: `legacy.so` (or any other provider) must be compiled
  against the same OpenSSL version as the libraries you are installing.
- **Package upgrades**: a `deb`/`rpm` upgrade does not touch the drop-in
  override file, so the custom OpenSSL remains active after an upgrade.
