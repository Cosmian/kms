use actix_web::{HttpResponse, post, web::Json};
use base64::{Engine as _, engine::general_purpose};
use cosmian_kms_crypto::crypto::anonymization::{
    AnoError, DateAggregator, HashMethod, Hasher, NoiseGenerator, NumberAggregator, NumberScaler,
    TimeUnit, WordMasker, WordPatternMasker, WordTokenizer,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Maximum allowed regex pattern length to mitigate `ReDoS` attacks.
const MAX_PATTERN_LEN: usize = 1024;

#[derive(Serialize, Debug)]
struct TokenizeErrorReply {
    code: u16,
    message: String,
}

/// Convert an `AnoError` into an HTTP 422 response.
fn ano_to_response(e: &AnoError) -> HttpResponse {
    let reply = TokenizeErrorReply {
        code: 422,
        message: e.to_string(),
    };
    HttpResponse::UnprocessableEntity().json(reply)
}

/// Convenience macro: return HTTP 422 from an `AnoError` result.
macro_rules! try_ano {
    ($expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => return ano_to_response(&e),
        }
    };
}


#[derive(Serialize)]
struct TokenizeResponse {
    result: Value,
}

#[derive(Deserialize)]
pub(crate) struct HashRequest {
    /// Input string to hash.
    data: String,
    /// Hash algorithm: "SHA2", "SHA3", or "Argon2".
    method: String,
    /// Optional base64-encoded salt bytes.
    salt: Option<String>,
}

/// Hash a string using SHA2, SHA3, or Argon2.
#[post("/hash")]
pub(crate) async fn hash(body: Json<HashRequest>) -> HttpResponse {
    let salt = match body.salt.as_deref() {
        Some(s) => Some(try_ano!(
            general_purpose::STANDARD
                .decode(s)
                .map_err(|e| AnoError::AnonymizationError(format!("invalid base64 salt: {e}")))
        )),
        None => None,
    };
    let method = try_ano!(HashMethod::new(&body.method, salt));
    let hasher = Hasher::new(method);
    let result = try_ano!(hasher.apply_str(&body.data));
    HttpResponse::Ok().json(TokenizeResponse {
        result: Value::String(result),
    })
}


#[derive(Deserialize)]
pub(crate) struct NoiseRequest {
    /// Value to add noise to.
    data: Value,
    /// One of: "float", "integer", "date".
    data_type: String,
    /// Distribution: "Gaussian", "Laplace", or "Uniform".
    method: String,
    /// Used with `new_with_parameters` (Gaussian/Laplace).
    mean: Option<f64>,
    std_dev: Option<f64>,
    /// Used with `new_with_bounds` (Gaussian/Laplace/Uniform).
    min_bound: Option<f64>,
    max_bound: Option<f64>,
}

/// Add statistical noise to a float, integer, or RFC3339 date.
#[post("/noise")]
pub(crate) async fn noise(body: Json<NoiseRequest>) -> HttpResponse {
    let mut noise_gen: NoiseGenerator<f64> = if let (Some(mean), Some(std_dev)) =
        (body.mean, body.std_dev)
    {
        try_ano!(NoiseGenerator::new_with_parameters(&body.method, mean, std_dev))
    } else if let (Some(min), Some(max)) = (body.min_bound, body.max_bound) {
        try_ano!(NoiseGenerator::new_with_bounds(&body.method, min, max))
    } else {
        return HttpResponse::UnprocessableEntity().json(TokenizeErrorReply {
            code: 422,
            message: "provide either (mean + std_dev) or (min_bound + max_bound)".to_owned(),
        });
    };

    let result: Value = match body.data_type.as_str() {
        "float" => {
            let v = try_ano!(body
                .data
                .as_f64()
                .ok_or_else(|| AnoError::AnonymizationError(
                    "data must be a number for data_type=float".to_owned()
                )));
            Value::from(noise_gen.apply_on_float(v))
        }
        "integer" => {
            let v = try_ano!(body
                .data
                .as_i64()
                .ok_or_else(|| AnoError::AnonymizationError(
                    "data must be an integer for data_type=integer".to_owned()
                )));
            Value::from(noise_gen.apply_on_int(v))
        }
        "date" => {
            let s = try_ano!(body
                .data
                .as_str()
                .ok_or_else(|| AnoError::AnonymizationError(
                    "data must be a string (RFC3339) for data_type=date".to_owned()
                )));
            Value::String(try_ano!(noise_gen.apply_on_date(s)))
        }
        other => {
            return HttpResponse::UnprocessableEntity().json(TokenizeErrorReply {
                code: 422,
                message: format!("unknown data_type '{other}'; expected float, integer, or date"),
            });
        }
    };
    HttpResponse::Ok().json(TokenizeResponse { result })
}

#[derive(Deserialize)]
pub(crate) struct WordListRequest {
    /// Input text.
    data: String,
    /// Words to mask or tokenize.
    words: Vec<String>,
}

/// Replace sensitive words with "XXXX".
#[post("/word-mask")]
pub(crate) async fn word_mask(body: Json<WordListRequest>) -> HttpResponse {
    let word_refs: Vec<&str> = body.words.iter().map(String::as_str).collect();
    let masker = WordMasker::new(&word_refs);
    let result = masker.apply(&body.data);
    HttpResponse::Ok().json(TokenizeResponse {
        result: Value::String(result),
    })
}

/// Replace sensitive words with random hex tokens (consistent within one request).
#[post("/word-tokenize")]
pub(crate) async fn word_tokenize(body: Json<WordListRequest>) -> HttpResponse {
    let word_refs: Vec<&str> = body.words.iter().map(String::as_str).collect();
    let tokenizer = try_ano!(WordTokenizer::new(&word_refs));
    let result = tokenizer.apply(&body.data);
    HttpResponse::Ok().json(TokenizeResponse {
        result: Value::String(result),
    })
}


#[derive(Deserialize)]
pub(crate) struct WordPatternRequest {
    /// Input text.
    data: String,
    /// Regex pattern to match (max 1024 chars — `ReDoS` mitigation).
    pattern: String,
    /// Replacement string.
    replace: String,
}

/// Replace all regex-matched substrings with a replacement string.
#[post("/word-pattern-mask")]
pub(crate) async fn word_pattern_mask(body: Json<WordPatternRequest>) -> HttpResponse {
    if body.pattern.len() > MAX_PATTERN_LEN {
        return HttpResponse::UnprocessableEntity().json(TokenizeErrorReply {
            code: 422,
            message: format!(
                "pattern too long (max {MAX_PATTERN_LEN} chars, got {})",
                body.pattern.len()
            ),
        });
    }
    let masker = try_ano!(WordPatternMasker::new(&body.pattern, &body.replace));
    let result = masker.apply(&body.data);
    HttpResponse::Ok().json(TokenizeResponse {
        result: Value::String(result),
    })
}


#[derive(Deserialize)]
pub(crate) struct AggregateNumberRequest {
    /// Number to round (float or integer depending on `data_type`).
    data: Value,
    /// One of: "float", "integer".
    data_type: String,
    /// Power of ten to round to (e.g. 2 → round to nearest 100).
    power_of_ten: i32,
}

/// Round a number to the nearest power of ten.
#[post("/aggregate-number")]
pub(crate) async fn aggregate_number(body: Json<AggregateNumberRequest>) -> HttpResponse {
    let agg = try_ano!(NumberAggregator::new(body.power_of_ten));
    let result: String = match body.data_type.as_str() {
        "float" => {
            let v = try_ano!(body
                .data
                .as_f64()
                .ok_or_else(|| AnoError::AnonymizationError(
                    "data must be a number for data_type=float".to_owned()
                )));
            agg.apply_on_float(v)
        }
        "integer" => {
            let v = try_ano!(body
                .data
                .as_i64()
                .ok_or_else(|| AnoError::AnonymizationError(
                    "data must be an integer for data_type=integer".to_owned()
                )));
            agg.apply_on_int(v)
        }
        other => {
            return HttpResponse::UnprocessableEntity().json(TokenizeErrorReply {
                code: 422,
                message: format!("unknown data_type '{other}'; expected float or integer"),
            });
        }
    };
    HttpResponse::Ok().json(TokenizeResponse {
        result: Value::String(result),
    })
}


#[derive(Deserialize)]
pub(crate) struct AggregateDateRequest {
    /// RFC3339 date string to truncate.
    data: String,
    /// Truncation precision: "Second", "Minute", "Hour", "Day", "Month", or "Year".
    time_unit: String,
}

/// Truncate an RFC3339 date to the specified time unit.
#[post("/aggregate-date")]
pub(crate) async fn aggregate_date(body: Json<AggregateDateRequest>) -> HttpResponse {
    let unit = try_ano!(TimeUnit::try_from(body.time_unit.as_str()));
    let agg = DateAggregator::new(unit);
    let result = try_ano!(agg.apply_on_date(&body.data));
    HttpResponse::Ok().json(TokenizeResponse {
        result: Value::String(result),
    })
}


#[derive(Deserialize)]
pub(crate) struct ScaleNumberRequest {
    /// Number to scale (float or integer depending on `data_type`).
    data: Value,
    /// One of: "float", "integer".
    data_type: String,
    /// Mean of the original data distribution.
    mean: f64,
    /// Standard deviation of the original data distribution (non-zero).
    std_deviation: f64,
    /// Scaling factor.
    scale: f64,
    /// Translation factor.
    translate: f64,
}

/// Normalize and scale a number using z-score transformation.
#[post("/scale-number")]
pub(crate) async fn scale_number(body: Json<ScaleNumberRequest>) -> HttpResponse {
    let scaler = try_ano!(NumberScaler::new(
        body.mean,
        body.std_deviation,
        body.scale,
        body.translate,
    ));
    let result: Value = match body.data_type.as_str() {
        "float" => {
            let v = try_ano!(body
                .data
                .as_f64()
                .ok_or_else(|| AnoError::AnonymizationError(
                    "data must be a number for data_type=float".to_owned()
                )));
            Value::from(scaler.apply_on_float(v))
        }
        "integer" => {
            let v = try_ano!(body
                .data
                .as_i64()
                .ok_or_else(|| AnoError::AnonymizationError(
                    "data must be an integer for data_type=integer".to_owned()
                )));
            Value::from(scaler.apply_on_int(v))
        }
        other => {
            return HttpResponse::UnprocessableEntity().json(TokenizeErrorReply {
                code: 422,
                message: format!("unknown data_type '{other}'; expected float or integer"),
            });
        }
    };
    HttpResponse::Ok().json(TokenizeResponse { result })
}
