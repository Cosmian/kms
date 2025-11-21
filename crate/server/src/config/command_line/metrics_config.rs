use clap::Args;
use serde::{Deserialize, Serialize};

const DEFAULT_METRICS_PORT: u16 = 9099;

#[derive(Args, Clone, Deserialize, Serialize, Debug)]
#[serde(default)]
pub struct MetricsConfig {
    /// Enable metrics endpoint for OTLP Collector scraping
    #[clap(long, env = "KMS_METRICS_ENABLED", verbatim_doc_comment)]
    pub metrics_enabled: bool,

    /// The metrics server port
    #[clap(long, env = "KMS_METRICS_PORT", default_value_t = DEFAULT_METRICS_PORT, verbatim_doc_comment)]
    pub metrics_port: u16,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            metrics_enabled: false,
            metrics_port: DEFAULT_METRICS_PORT,
        }
    }
}
