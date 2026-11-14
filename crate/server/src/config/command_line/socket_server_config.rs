use std::fmt::Display;

use clap::Args;
use clap_config_fallback::ConfigArgs;
use serde::{Deserialize, Serialize};

const DEFAULT_SOCKET_SERVER_PORT: u16 = 5696;
#[cfg(target_os = "windows")]
const DEFAULT_SOCKET_SERVER_HOSTNAME: &str = "127.0.0.1";
#[cfg(not(target_os = "windows"))]
const DEFAULT_SOCKET_SERVER_HOSTNAME: &str = "0.0.0.0";

#[derive(Args, ConfigArgs, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SocketServerConfig {
    /// Start the KMIP socket server?
    /// If this is set to true, the TLS config must be provided, featuring
    /// a server PKCS#12 file and a client certificate authority certificate file
    #[clap(
        long = "socket-server-start",
        id = "socket_server_start",
        value_name = "SOCKET_SERVER_START",
        env = "KMS_SOCKET_SERVER_START",
        default_value_t = false
    )]
    #[serde(rename = "socket_server_start")]
    pub start: bool,

    /// The KMS socket server port
    #[clap(long = "socket-server-port", id = "socket_server_port", value_name = "SOCKET_SERVER_PORT", env = "KMS_SOCKET_SERVER_PORT", default_value_t = DEFAULT_SOCKET_SERVER_PORT)]
    #[serde(rename = "socket_server_port")]
    pub port: u16,

    /// The KMS socket server hostname
    #[clap(long = "socket-server-hostname", id = "socket_server_hostname", value_name = "SOCKET_SERVER_HOSTNAME", env = "KMS_SOCKET_SERVER_HOSTNAME", default_value = DEFAULT_SOCKET_SERVER_HOSTNAME)]
    #[serde(rename = "socket_server_hostname")]
    pub hostname: String,
}

impl Display for SocketServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tls socket: {}:{}", self.hostname, self.port)
    }
}

impl std::fmt::Debug for SocketServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{self}"))
    }
}

impl Default for SocketServerConfig {
    fn default() -> Self {
        Self {
            start: false,
            port: DEFAULT_SOCKET_SERVER_PORT,
            hostname: DEFAULT_SOCKET_SERVER_HOSTNAME.to_owned(),
        }
    }
}
