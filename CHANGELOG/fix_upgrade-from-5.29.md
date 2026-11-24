## Bug Fixes

### Packaging
- Keep `cosmian_kms.service` enabled and running across Debian and RPM upgrades: the post-remove script of 5.29.0 and earlier stops and disables the unit during an upgrade. The `preinst` / `%pre` scripts now record the state, `postinst` / `%posttrans` restore it (the service restarts on the new binary), and `postrm` / `%postun` stop and disable the unit on removal only
- Keep `kms.toml`, `data` and `logs` across Windows installer upgrades: a silent or "don't uninstall" reinstall no longer overwrites `kms.toml` (the packaged template is written to `kms.toml.new`), and "uninstall before installing" saves and restores `kms.toml`, `data` and `logs` around the old uninstaller

## Documentation

- Upgrade guide 5.x to 6.0: no rolling upgrade (stop every node), upgrade `ckms` with the server, package and installer behaviour, FIPS build restrictions, Vault-token-only authentication, downgrade of `kms.toml`; fix the IV Length row for FIPS builds

## Testing

- `test_windows_package.ps1` reinstalls over the running install and checks that `kms.toml` is kept and `kms.toml.new` is written
- Container proof (systemd, arm64, ubuntu 24.04 and rockylinux 9): a 5.29.0 deb/rpm upgraded to the fixed package stays enabled and running with its edited `kms.toml`; the 5.29.0 package reinstalled over itself ends disabled and stopped
