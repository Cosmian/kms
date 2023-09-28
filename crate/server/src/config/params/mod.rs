mod db_params;
mod http_params;
mod server_params;
mod tee_params;

pub use db_params::DbParams;
pub use http_params::HttpParams;
pub use server_params::ServerParams;
pub use tee_params::TeeParams;

use super::command_line::BootstrapServerConfig;

pub type BootstrapServerParams = BootstrapServerConfig;
