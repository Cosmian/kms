## Build

### CLI

- Embed a Windows `VERSIONINFO` resource in `ckms.exe` (`FileDescription`, `FileVersion`,
  `ProductName`, `ProductVersion`, `CompanyName`, `LegalCopyright`, `Language`) via
  `winresource` in `crate/clients/ckms/build.rs`, so the Details tab in Windows Explorer is
  populated.

### Server

- Embed the same `VERSIONINFO` resource in `cosmian_kms.exe` via
  `crate/server/build.rs`.

### PKCS#11 / CNG

- Embed a `VERSIONINFO` resource (with `FILETYPE = VFT_DLL`) in `cosmian_pkcs11.dll` and
  `cosmian_cng.dll` via `crate/clients/pkcs11/provider/build.rs` and
  `crate/clients/cng/build.rs`.


## Documentation

### CLI

- Document why the Windows CI signing certificate (Azure Artifact Signing "Public Trust
  Test" profile) is not trusted by default, why "Catalog Signatures" is expected to be
  empty for a directly Authenticode-signed binary, and how to trust the certificate on an
  internal test machine only, in `documentation/docs/kms_clients/installation.md`.
