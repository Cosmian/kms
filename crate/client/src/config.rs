use cosmian_http_client::HttpClientConfig;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct RestClientConfig {
    pub http_config: HttpClientConfig,
}

impl Default for RestClientConfig {
    fn default() -> Self {
        Self {
            http_config: HttpClientConfig {
                server_url: "http://0.0.0.0:6668".to_owned(),
                ..HttpClientConfig::default()
            },
        }
    }
}
