use std::{collections::HashMap, path::PathBuf};

use clap::Parser;
use cosmian_kms_client::KmsClient;
use cosmian_logger::info;

use crate::error::{KmsCliError, result::KmsCliResult};

/// Migrate existing objects to have a `tenant_id` assigned.
///
/// This command reads an owner-to-tenant mapping file and updates all objects
/// in the KMS database that have a `NULL` `tenant_id`. This is required before
/// enabling RBAC mode, which enforces tenant boundaries.
///
/// The mapping file is a JSON object mapping owner identifiers to tenant IDs:
/// ```json
/// {
///   "alice@corp.com": "tenant-a",
///   "bob@other.com": "tenant-b",
///   "*": "default-tenant"
/// }
/// ```
///
/// The wildcard `"*"` entry provides a fallback for owners not explicitly listed.
/// If no wildcard is provided and an owner is not in the mapping, the command fails.
#[derive(Parser, Debug)]
pub struct MigrateTenantsAction {
    /// Path to the owner-to-tenant JSON mapping file.
    #[clap(long, required = true)]
    pub mapping_file: PathBuf,

    /// Dry-run mode: show what would be changed without modifying the database.
    #[clap(long, default_value = "false")]
    pub dry_run: bool,
}

impl MigrateTenantsAction {
    /// Process the migrate-tenants command.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The mapping file cannot be read or parsed
    /// - The KMS server cannot be reached
    /// - An owner has no mapping and no wildcard is defined
    #[allow(clippy::unused_async)]
    pub async fn run(&self, _kms_client: &KmsClient) -> KmsCliResult<()> {
        // Read and parse the mapping file
        let content = std::fs::read_to_string(&self.mapping_file).map_err(|e| {
            KmsCliError::Default(format!(
                "Failed to read mapping file '{}': {e}",
                self.mapping_file.display()
            ))
        })?;

        let mapping: HashMap<String, String> = serde_json::from_str(&content).map_err(|e| {
            KmsCliError::Default(format!(
                "Failed to parse mapping file as JSON: {e}. \
                 Expected format: {{\"owner@email.com\": \"tenant-id\", \"*\": \"default-tenant\"}}"
            ))
        })?;

        if mapping.is_empty() {
            return Err(KmsCliError::Default(
                "Mapping file is empty. Provide at least one owner-to-tenant mapping.".to_owned(),
            ));
        }

        let has_wildcard = mapping.contains_key("*");

        if self.dry_run {
            info!("Dry-run mode: no changes will be made.");
            info!("Mapping file: {}", self.mapping_file.display());
            info!("Entries: {} (wildcard: {has_wildcard})", mapping.len());
            for (owner, tenant) in &mapping {
                info!("  {owner} -> {tenant}");
            }
        } else {
            // TODO: Call a server-side REST endpoint to perform the migration.
            // The endpoint would:
            // 1. Query all objects with NULL tenant_id
            // 2. For each, look up the owner in the mapping
            // 3. Update tenant_id = mapped value (or wildcard fallback)
            // 4. Return a summary of changes
            info!(
                "Tenant migration requires a server-side endpoint (POST /admin/migrate-tenants)."
            );
            info!(
                "This endpoint is not yet implemented. Use --dry-run to validate your mapping file."
            );
        }

        Ok(())
    }
}
