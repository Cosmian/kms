use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::tokenize::{
        AggregateDateAction, AggregateNumberAction, HashAction, NoiseAction, ScaleNumberAction,
        WordMaskAction, WordPatternMaskAction, WordTokenizeAction,
    },
    error::result::KmsCliResult,
};

/// The server must return HTTP 200 for a basic SHA2 hash request.
#[tokio::test]
async fn test_hash_sha2() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    HashAction {
        data: "hello world".to_owned(),
        method: "SHA2".to_owned(),
        salt: None,
    }
    .run(ctx.get_owner_client())
    .await
}

/// SHA3 hashing of the same input must succeed.
#[tokio::test]
async fn test_hash_sha3() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    HashAction {
        data: "hello world".to_owned(),
        method: "SHA3".to_owned(),
        salt: None,
    }
    .run(ctx.get_owner_client())
    .await
}

/// Gaussian noise on a float must succeed.
#[tokio::test]
async fn test_noise_gaussian_float() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    NoiseAction {
        data: "42.5".to_owned(),
        data_type: "float".to_owned(),
        method: "Gaussian".to_owned(),
        mean: Some(0.0),
        std_dev: Some(1.0),
        min_bound: None,
        max_bound: None,
    }
    .run(ctx.get_owner_client())
    .await
}

/// Uniform noise on an integer must succeed.
#[tokio::test]
async fn test_noise_uniform_integer() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    NoiseAction {
        data: "100".to_owned(),
        data_type: "integer".to_owned(),
        method: "Uniform".to_owned(),
        mean: None,
        std_dev: None,
        min_bound: Some(-10.0),
        max_bound: Some(10.0),
    }
    .run(ctx.get_owner_client())
    .await
}

/// Word masking must succeed when a known word is contained in the text.
#[tokio::test]
async fn test_word_mask() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    WordMaskAction {
        data: "My name is Alice and I know Bob".to_owned(),
        words: vec!["Alice".to_owned(), "Bob".to_owned()],
    }
    .run(ctx.get_owner_client())
    .await
}

/// Word tokenization with known words must succeed.
#[tokio::test]
async fn test_word_tokenize() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    WordTokenizeAction {
        data: "Contact Alice at alice@example.com".to_owned(),
        words: vec!["Alice".to_owned(), "alice@example.com".to_owned()],
    }
    .run(ctx.get_owner_client())
    .await
}

/// Pattern masking via a simple regex must succeed.
#[tokio::test]
async fn test_word_pattern_mask() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    WordPatternMaskAction {
        data: "Call me at 555-1234".to_owned(),
        pattern: r"\d{3}-\d{4}".to_owned(),
        replace: "XXX-XXXX".to_owned(),
    }
    .run(ctx.get_owner_client())
    .await
}

/// Number aggregation (integer) must succeed.
#[tokio::test]
async fn test_aggregate_number_integer() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    AggregateNumberAction {
        data: "1234".to_owned(),
        data_type: "integer".to_owned(),
        power_of_ten: 2,
    }
    .run(ctx.get_owner_client())
    .await
}

/// Date aggregation to Day precision must succeed.
#[tokio::test]
async fn test_aggregate_date() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    AggregateDateAction {
        data: "2024-07-15T13:45:30Z".to_owned(),
        time_unit: "Day".to_owned(),
    }
    .run(ctx.get_owner_client())
    .await
}

/// Number scaling (float) must succeed.
#[tokio::test]
async fn test_scale_number_float() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    ScaleNumberAction {
        data: "75.0".to_owned(),
        data_type: "float".to_owned(),
        mean: 50.0,
        std_deviation: 10.0,
        scale: 1.0,
        translate: 0.0,
    }
    .run(ctx.get_owner_client())
    .await
}
