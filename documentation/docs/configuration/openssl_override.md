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

Place the libraries anywhere that is accessible to the `cosmian_kms` service
(i.e. **not** under `/home/` — the systemd unit sets `ProtectHome=yes`).
Recommended locations: `/opt/` or `/usr/local/lib/`.

Vendor CC/FIPS packages commonly ship with a nested `usr/local/` tree inside
the archive.  Copy the whole folder as-is:

```bash
sudo cp -r /path/to/openssl-<version>-linux-x86_64 /usr/local/lib/
```

Resulting layout:

```text
/usr/local/lib/openssl-<version>-linux-x86_64/
  usr/
    local/
      lib64/
        libssl.so.3
        libcrypto.so.3
        ossl-modules/
          fips.so
          legacy.so
      ssl/
        openssl.cnf
        fipsmodule.cnf
```

In the override.conf you then reference the nested `usr/local/lib64/` path:

```ini
LD_LIBRARY_PATH=/usr/local/lib/openssl-<version>-linux-x86_64/usr/local/lib64
OPENSSL_MODULES=/usr/local/lib/openssl-<version>-linux-x86_64/usr/local/lib64/ossl-modules
```

If the archive extracts directly to `lib64/` at the top level (no `usr/local/`
subdirectory), use a simpler install path such as `/opt/openssl-custom/` and
reference `lib64/` directly.

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
# Required when OIDC/JWKS auth is enabled: the default unit blocks outbound
# traffic to public IPs.  See "Network firewall" below.
IPAddressAllow=any
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

## Network firewall

!!! warning "Affects OIDC / JWKS authentication"
    The default systemd unit ships with `IPAddressDeny=any` and only allows
    traffic to localhost and RFC-1918 private ranges:

    ```ini
    IPAddressDeny=any
    IPAddressAllow=localhost
    IPAddressAllow=10.0.0.0/8
    IPAddressAllow=172.16.0.0/12
    IPAddressAllow=192.168.0.0/16
    ```

    When `jwt_auth_provider` is configured, the KMS fetches JWKS keys from a
    **public** OIDC endpoint (e.g. `login.microsoftonline.com`) at startup.
    Because the endpoint's IP is not in the allowed list, the BPF firewall
    silently drops the outbound SYN packets — the service hangs indefinitely
    at the `Refreshing JWKS` log line and never starts listening.

### Fix: allow outbound HTTPS in the drop-in

Add `IPAddressAllow=any` to the override.conf drop-in (taking precedence over
the `IPAddressDeny=any` in the unit):

```ini
[Service]
# … OpenSSL entries …
IPAddressAllow=any
```

If a stricter policy is preferred, add only the OIDC provider's IP ranges
instead of `any`.  For Microsoft Entra ID / Azure AD (as of 2026), the range
is documented in the
[Microsoft 365 IP address list](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges).

!!! note "FIPS provider setup for custom builds"
    If the custom OpenSSL was compiled with `OPENSSLDIR=/usr/local/ssl` (check
    via `openssl version -a`), the FIPS provider looks for its configuration at
    that path regardless of `OPENSSL_CONF`.  Create the path and run
    `fipsinstall` before starting the service:

    ```bash
    sudo mkdir -p /usr/local/ssl
    sudo env LD_LIBRARY_PATH=/opt/openssl-custom/lib64 \
      /opt/openssl-custom/bin/openssl fipsinstall \
      -module /opt/openssl-custom/lib64/ossl-modules/fips.so \
      -out /usr/local/ssl/fipsmodule.cnf

    # Create a minimal openssl.cnf at the compiled-in OPENSSLDIR
    sudo tee /usr/local/ssl/openssl.cnf > /dev/null <<'EOF'
    openssl_conf = openssl_init
    config_diagnostics = 1
    .include /usr/local/ssl/fipsmodule.cnf

    [openssl_init]
    providers = provider_sect

    [provider_sect]
    fips = fips_sect
    default = default_sect

    [default_sect]
    activate = 1
    EOF
    ```

    Verify FIPS loads before restarting the service:

    ```bash
    sudo env LD_LIBRARY_PATH=/opt/openssl-custom/lib64 \
      OPENSSL_MODULES=/opt/openssl-custom/lib64/ossl-modules \
      /opt/openssl-custom/bin/openssl list -providers
    # Expected: both "default" and "fips" providers show status: active
    ```

Then reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart cosmian_kms
```

!!! note "ProtectHome restriction"
    The systemd unit sets `ProtectHome=yes`.  Custom OpenSSL builds placed
    under `/home/…` are inaccessible to the service.  Install custom builds
    under `/opt/` or `/usr/local/` so the service can load them.

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
