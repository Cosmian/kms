use clap::Parser;
use cosmian_kms_client::KmsClient;
use serde::Serialize;
use serde_json::Value;

use super::TokenizeResponse;
use crate::error::result::KmsCliResult;

#[derive(Serialize)]
pub(super) struct AggregateNumberRequest<'a> {
    data: Value,
    data_type: &'a str,
    power_of_ten: i32,
}

/// Round a number to the nearest power of ten.
#[derive(Parser, Debug)]
pub struct AggregateNumberAction {
    /// Number to round.
    #[clap(long, short = 'd')]
    pub data: String,

    /// Data type: float or integer.
    #[clap(long, short = 't', default_value = "integer")]
    pub data_type: String,

    /// Power of ten (e.g., 2 rounds to the nearest 100).
    #[clap(long, short = 'p', default_value = "1")]
    pub power_of_ten: i32,
}

impl AggregateNumberAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let data: Value =
            match self.data_type.as_str() {
                "float" => Value::from(self.data.parse::<f64>().map_err(|e| {
                    crate::error::KmsCliError::Default(format!("invalid float: {e}"))
                })?),
                _ => Value::from(self.data.parse::<i64>().map_err(|e| {
                    crate::error::KmsCliError::Default(format!("invalid integer: {e}"))
                })?),
            };
        let req = AggregateNumberRequest {
            data,
            data_type: &self.data_type,
            power_of_ten: self.power_of_ten,
        };
        let resp: TokenizeResponse = kms_rest_client.tokenize("aggregate-number", &req).await?;
        resp.print();
        Ok(())
    }
}
