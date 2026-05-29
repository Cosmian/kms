## CI

- fix(nix): replace `builtins.fetchTarball` with `pkgs.fetchurl` for `.crate` sources — Nix doesn't recognize the `.crate` extension for unpacking; use `.tar.gz` name alias instead
- fix(ci): reduce `http-connections` to 8 in Nix config to mitigate macOS "Invalid multi handle" curl daemon bug
- fix(ci): skip Docker cleanup step on macOS runners in packaging workflow

## Testing

- test(vectors): add `fortigate_credential_type` non-regression vector — validates numeric `CredentialType` enum (`0x00000001`) parsing in KMIP 1.0 Authentication ([#824](https://github.com/Cosmian/kms/issues/824))
- test(vectors): add `fortigate_locate_filter` non-regression vector — validates Locate with `TemplateAttribute` name filter returns distinct keys ([#824](https://github.com/Cosmian/kms/issues/824))
