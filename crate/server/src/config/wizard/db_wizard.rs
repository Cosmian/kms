//! Database configuration step of the KMS configuration wizard.

#![allow(unreachable_pub)]

use std::path::PathBuf;

use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};

use crate::{
    config::{DatabaseType, MainDBConfig},
    error::KmsError,
    result::KResult,
};

pub fn configure_db() -> KResult<MainDBConfig> {
    let theme = ColorfulTheme::default();

    #[cfg(not(feature = "non-fips"))]
    let db_variants = DatabaseType::FIPS_VARIANTS;
    #[cfg(feature = "non-fips")]
    let db_variants = DatabaseType::NON_FIPS_VARIANTS;

    let db_idx = Select::with_theme(&theme)
        .with_prompt("Select database type")
        .items(&db_variants.iter().map(|v| v.as_str()).collect::<Vec<_>>())
        .default(0)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let selected_db = db_variants
        .get(db_idx)
        .ok_or_else(|| KmsError::ServerError("Invalid database selection".to_owned()))?;
    let database_type = Some(selected_db.as_str().to_owned());
    let selected = selected_db.as_str();

    let database_url: Option<String> = if matches!(selected, "postgresql" | "mysql") {
        let default = match selected {
            "postgresql" => "postgresql://user:password@localhost:5432/kms",
            "mysql" => "mysql://user:password@localhost:3306/kms",
            _ => "",
        };
        let url: String = Input::with_theme(&theme)
            .with_prompt("Database URL")
            .with_initial_text(default)
            .interact_text()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
        Some(url)
    } else if selected == "redis-findex" {
        let url: String = Input::with_theme(&theme)
            .with_prompt("Redis database URL")
            .with_initial_text("redis://localhost:6379")
            .interact_text()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
        Some(url)
    } else {
        None
    };

    let sqlite_path: PathBuf = if selected == "sqlite" {
        let p: String = Input::with_theme(&theme)
            .with_prompt("SQLite data directory")
            .default("./sqlite-data".to_owned())
            .interact_text()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
        PathBuf::from(p)
    } else {
        PathBuf::from("./sqlite-data")
    };

    #[cfg(feature = "non-fips")]
    let redis_master_password: Option<String> = if selected == "redis-findex" {
        let pwd: String = dialoguer::Password::with_theme(&theme)
            .with_prompt("Redis master password")
            .interact()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
        Some(pwd)
    } else {
        None
    };

    let clear_database: bool = Confirm::with_theme(&theme)
        .with_prompt("⚠  Clear database on start? (DELETES ALL DATA)")
        .default(false)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let max_connections_str: String = Input::with_theme(&theme)
        .with_prompt("Max database connections (leave blank for default)")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
    let max_connections: Option<u32> = if max_connections_str.trim().is_empty() {
        None
    } else {
        max_connections_str.trim().parse().ok()
    };

    let unwrapped_cache_max_age: u64 = Input::with_theme(&theme)
        .with_prompt("Unwrapped key cache max age (minutes)")
        .default(15_u64)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    Ok(MainDBConfig {
        database_type,
        database_url,
        sqlite_path,
        #[cfg(feature = "non-fips")]
        redis_master_password,
        clear_database,
        max_connections,
        unwrapped_cache_max_age,
    })
}
