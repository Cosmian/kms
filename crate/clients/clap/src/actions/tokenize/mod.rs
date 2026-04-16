use crate::error::result::KmsCliResult;
use clap::Parser;
use cosmian_kms_client::KmsClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod aggregate_date;
pub mod aggregate_number;
pub mod hash;
pub mod noise;
pub mod scale_number;
pub mod word_mask;
pub mod word_pattern_mask;
pub mod word_tokenize;

pub use aggregate_date::AggregateDateAction;
pub use aggregate_number::AggregateNumberAction;
pub use hash::HashAction;
pub use noise::NoiseAction;
pub use scale_number::ScaleNumberAction;
pub use word_mask::WordMaskAction;
pub use word_pattern_mask::WordPatternMaskAction;
pub use word_tokenize::WordTokenizeAction;

/// Common response wrapper for all tokenize endpoints.
#[derive(Deserialize, Serialize)]
pub(super) struct TokenizeResponse {
    result: Value,
}

impl TokenizeResponse {
    #[allow(clippy::print_stdout)] // intentional: CLI output to stdout
    pub(super) fn print(&self) {
        println!("{}", self.result);
    }
}

/// Shared request body for word-mask and word-tokenize endpoints.
#[derive(Serialize)]
pub(super) struct WordListRequest<'a> {
    pub(super) data: &'a str,
    pub(super) words: &'a [String],
}

/// Anonymization utilities: hash, noise, word masking, pattern masking, aggregation, and scaling.
///
/// All methods call the KMS `/tokenize/{method}` REST endpoints.
/// Requires a KMS built with the `non-fips` feature.
#[derive(Parser)]
pub enum TokenizeCommands {
    /// Hash a string with SHA2, SHA3, or Argon2.
    Hash(HashAction),
    /// Add statistical noise to a number or date.
    Noise(NoiseAction),
    /// Replace sensitive words with "XXXX".
    WordMask(WordMaskAction),
    /// Replace sensitive words with consistent random hex tokens.
    WordTokenize(WordTokenizeAction),
    /// Replace regex-matched substrings with a replacement string.
    WordPatternMask(WordPatternMaskAction),
    /// Round a number to the nearest power of ten.
    AggregateNumber(AggregateNumberAction),
    /// Truncate a date to a specified time unit.
    AggregateDate(AggregateDateAction),
    /// Normalize and scale a number using z-score transformation.
    ScaleNumber(ScaleNumberAction),
}

impl TokenizeCommands {
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Hash(action) => action.run(kms_rest_client).await?,
            Self::Noise(action) => action.run(kms_rest_client).await?,
            Self::WordMask(action) => action.run(kms_rest_client).await?,
            Self::WordTokenize(action) => action.run(kms_rest_client).await?,
            Self::WordPatternMask(action) => action.run(kms_rest_client).await?,
            Self::AggregateNumber(action) => action.run(kms_rest_client).await?,
            Self::AggregateDate(action) => action.run(kms_rest_client).await?,
            Self::ScaleNumber(action) => action.run(kms_rest_client).await?,
        }
        Ok(())
    }
}
