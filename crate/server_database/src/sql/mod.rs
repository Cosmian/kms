//! This is WIP
//! This is an attempt at sharing the SQL code across the different databases
//! The entry point is `SqlMainStore`

mod database;
pub use database::SqlDatabase;
mod main_store;
pub use main_store::SqlMainStore;
mod migrate;
mod object_store;
