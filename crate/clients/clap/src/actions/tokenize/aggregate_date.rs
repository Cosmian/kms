use clap::Parser;
use cosmian_kms_client::KmsClient;
use serde::Serialize;

use super::TokenizeResponse;
use crate::error::result::KmsCliResult;

#[derive(Serialize)]
pub(super) struct AggregateDateRequest<'a> {
    data: &'a str,
    time_unit: &'a str,
}

/// Truncate an RFC3339 date to a specified time unit.
#[derive(Parser, Debug)]
pub struct AggregateDateAction {
    /// RFC3339 date string (e.g. "2024-07-15T13:45:00Z").
    #[clap(long, short = 'd')]
    pub data: String,

    /// Time unit precision: Second, Minute, Hour, Day, Month, or Year.
    #[clap(long, short = 'u', default_value = "Day")]
    pub time_unit: String,
}

impl AggregateDateAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let req = AggregateDateRequest {
            data: &self.data,
            time_unit: &self.time_unit,
        };
        let resp: TokenizeResponse = kms_rest_client.tokenize("aggregate-date", &req).await?;
        resp.print();
        Ok(())
    }
}
