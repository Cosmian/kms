use std::fmt::Display;

use clap::Args;
use serde::{Deserialize, Serialize};

const DEFAULT_SOCKET_SERVER_PORT: u16 = 5696;
const DEFAULT_SOCKET_SERVER_HOSTNAME: &str = "0.0.0.0";

#[derive(Args, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SocketServerConfig {
    /// Start the KMIP socket server?
    /// If this is set to true, the TLS config nust be provided, featuring
    /// a server PKCS#12 file and a client certificate authority certificate file
    #[clap(long, env = "KMS_SOCKET_SERVER_START", default_value_t = false)]
    pub socket_server_start: bool,

    /// The KMS socket server port
    #[clap(long, env = "KMS_SOCKET_SERVER_PORT", default_value_t = DEFAULT_SOCKET_SERVER_PORT)]
    pub socket_server_port: u16,

    /// The KMS socket server hostname
    #[clap(long, env = "KMS_SOCKET_SERVER_HOSTNAME", default_value = DEFAULT_SOCKET_SERVER_HOSTNAME)]
    pub socket_server_hostname: String,
}

impl Display for SocketServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tls socket: {}:{}",
            self.socket_server_hostname, self.socket_server_port
        )
    }
}

impl std::fmt::Debug for SocketServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", &self))
    }
}

impl Default for SocketServerConfig {
    fn default() -> Self {
        Self {
            socket_server_start: false,
            socket_server_port: DEFAULT_SOCKET_SERVER_PORT,
            socket_server_hostname: DEFAULT_SOCKET_SERVER_HOSTNAME.to_owned(),
        }
    }
}
