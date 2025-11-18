## About future versions

- Add future-ly supported version numbers in `SUPPORTED_API_VERSIONS` in `crate/server/src/routes/azure_ekm/mod.rs`
- Take into account that each version *might* support error status codes that were not previously supported, refer to `error.rs`.
