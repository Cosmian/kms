use clap::Parser;
use cosmian_kms_client::KmsClient;
use serde::Serialize;
use serde_json::Value;

use super::TokenizeResponse;
use crate::error::result::KmsCliResult;

#[derive(Serialize)]
pub(super) struct NoiseRequest<'a> {
    data: Value,
    data_type: &'a str,
    method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    mean: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    std_dev: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_bound: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_bound: Option<f64>,
}

/// Add statistical noise (Gaussian, Laplace, or Uniform) to a value.
#[derive(Parser, Debug)]
pub struct NoiseAction {
    /// Input value (float, integer, or RFC3339 date string).
    #[clap(long, short = 'd')]
    pub data: String,

    /// Data type: float, integer, or date.
    #[clap(long, short = 't', default_value = "float")]
    pub data_type: String,

    /// Noise distribution: Gaussian, Laplace, or Uniform.
    #[clap(long, short = 'm', default_value = "Gaussian")]
    pub method: String,

    /// Distribution mean (required for Gaussian/Laplace with parameters mode).
    #[clap(long)]
    pub mean: Option<f64>,

    /// Standard deviation (required for Gaussian/Laplace with parameters mode).
    #[clap(long)]
    pub std_dev: Option<f64>,

    /// Lower bound (required for bounds mode or Uniform).
    #[clap(long)]
    pub min_bound: Option<f64>,

    /// Upper bound (required for bounds mode or Uniform).
    #[clap(long)]
    pub max_bound: Option<f64>,
}

impl NoiseAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let data: Value =
            match self.data_type.as_str() {
                "float" => Value::from(self.data.parse::<f64>().map_err(|e| {
                    crate::error::KmsCliError::Default(format!("invalid float: {e}"))
                })?),
                "integer" => Value::from(self.data.parse::<i64>().map_err(|e| {
                    crate::error::KmsCliError::Default(format!("invalid integer: {e}"))
                })?),
                _ => Value::String(self.data.clone()),
            };
        let req = NoiseRequest {
            data,
            data_type: &self.data_type,
            method: &self.method,
            mean: self.mean,
            std_dev: self.std_dev,
            min_bound: self.min_bound,
            max_bound: self.max_bound,
        };
        let resp: TokenizeResponse = kms_rest_client.tokenize("noise", &req).await?;
        resp.print();
        Ok(())
    }
}
