## About future versions

- Add future-ly supported version numbers in `SUPPORTED_API_VERSIONS` in `crate/server/src/routes/azure_ekm/mod.rs`
- Take into account that each version *might* support error status codes that were not previously supported, refer to `error.rs`.

## Development guidelines

- For some reason, code editors might suggest to import the `cosmian_kmip` imports from the crate `cosmian_kms_client_utils`. Do not import from there, use that same crate `cosmian_kms_server_database` (mod.rs, line 9).
- Separate handlers to `handlers.rs` to ease out testing the API.
