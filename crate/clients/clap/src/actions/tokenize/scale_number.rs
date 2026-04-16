use clap::Parser;
use cosmian_kms_client::KmsClient;
use serde::Serialize;
use serde_json::Value;

use super::TokenizeResponse;
use crate::error::result::KmsCliResult;

#[derive(Serialize)]
pub(super) struct ScaleNumberRequest<'a> {
    data: Value,
    data_type: &'a str,
    mean: f64,
    std_deviation: f64,
    scale: f64,
    translate: f64,
}

/// Normalize and scale a number using z-score transformation.
#[derive(Parser, Debug)]
pub struct ScaleNumberAction {
    /// Number to scale.
    #[clap(long, short = 'd')]
    pub data: String,

    /// Data type: float or integer.
    #[clap(long, short = 't', default_value = "float")]
    pub data_type: String,

    /// Mean of the original data distribution.
    #[clap(long)]
    pub mean: f64,

    /// Standard deviation of the original data distribution (must be non-zero).
    #[clap(long)]
    pub std_deviation: f64,

    /// Scaling factor.
    #[clap(long, default_value = "1.0")]
    pub scale: f64,

    /// Translation factor.
    #[clap(long, default_value = "0.0")]
    pub translate: f64,
}

impl ScaleNumberAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let data: Value = match self.data_type.as_str() {
            "integer" => Value::from(self.data.parse::<i64>().map_err(|e| {
                crate::error::KmsCliError::Default(format!("invalid integer: {e}"))
            })?),
            _ => Value::from(self.data.parse::<f64>().map_err(|e| {
                crate::error::KmsCliError::Default(format!("invalid float: {e}"))
            })?),
        };
        let req = ScaleNumberRequest {
            data,
            data_type: &self.data_type,
            mean: self.mean,
            std_deviation: self.std_deviation,
            scale: self.scale,
            translate: self.translate,
        };
        let resp: TokenizeResponse = kms_rest_client.tokenize("scale-number", &req).await?;
        resp.print();
        Ok(())
    }
}
