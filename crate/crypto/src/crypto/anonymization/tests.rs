#![allow(clippy::assertions_on_result_states)]

use std::collections::HashSet;

use chrono::{DateTime, Datelike, Timelike};

use super::{
    AnoError, DateAggregator, HashMethod, Hasher, NoiseGenerator, NumberAggregator, NumberScaler,
    TimeUnit, WordMasker, WordPatternMasker, WordTokenizer,
};

#[test]
fn test_hash_sha2() -> Result<(), AnoError> {
    let hasher = Hasher::new(HashMethod::SHA2(None));
    let sha2_hash = hasher.apply_str("test sha2")?;
    assert_eq!(sha2_hash, "Px0txVYqBePXWF5K4xFn0Pa2mhnYA/jfsLtpIF70vJ8=");

    let hasher = Hasher::new(HashMethod::SHA2(Some(b"example salt".to_vec())));
    let sha2_hash_salt = hasher.apply_str("test sha2")?;
    assert_eq!(
        sha2_hash_salt,
        "d32KiG7kpZoaU2/Rqa+gbtaxDIKRA32nIxwhOXCaH1o="
    );

    Ok(())
}

#[test]
fn test_hash_sha3() -> Result<(), AnoError> {
    let hasher = Hasher::new(HashMethod::SHA3(None));
    let sha3_hash = hasher.apply_str("test sha3")?;
    assert_eq!(sha3_hash, "b8rRtRqnSFs8s12jsKSXHFcLf5MeHx8g6m4tvZq04/I=");

    let hasher = Hasher::new(HashMethod::SHA3(Some(b"example salt".to_vec())));
    let sha3_hash_salt = hasher.apply_str("test sha3")?;
    assert_eq!(
        sha3_hash_salt,
        "UBtIW7mX+cfdh3T3aPl/l465dBUbgKKZvMjZNNjwQ50="
    );

    Ok(())
}

#[test]
fn test_hash_argon2() -> Result<(), AnoError> {
    let hasher = Hasher::new(HashMethod::Argon2(b"example salt".to_vec()));
    let argon2_hash = hasher.apply_str("low entropy data")?;
    assert_eq!(argon2_hash, "JXiQyIYJAIMZoDKhA/BOKTo+142aTkDvtITEI7NXDEM=");

    Ok(())
}

#[test]
fn test_noise_gaussian_f64() -> Result<(), AnoError> {
    let mut gaussian_noise_generator = NoiseGenerator::new_with_parameters("Gaussian", 0.0, 1.0)?;
    let noisy_data = gaussian_noise_generator.apply_on_float(40.0);
    assert!((30.0..=50.0).contains(&noisy_data));

    let mut gaussian_noise_generator = NoiseGenerator::new_with_bounds("Gaussian", -5.0, 5.0)?;
    let noisy_data = gaussian_noise_generator.apply_on_float(40.0);
    assert!((30.0..=50.0).contains(&noisy_data));

    let res = NoiseGenerator::new_with_parameters("Gaussian", 0.0, -1.0);
    assert!(res.is_err());

    let res = NoiseGenerator::new_with_bounds("Gaussian", 1.0, 0.0);
    assert!(res.is_err());

    Ok(())
}

#[test]
fn test_noise_laplace_f64() -> Result<(), AnoError> {
    let mut laplace_noise_generator = NoiseGenerator::new_with_parameters("Laplace", 0.0, 1.0)?;
    let noisy_data = laplace_noise_generator.apply_on_float(40.0);
    // Wide bounds: Laplace β ≈ 0.71; P(|noise| > 30) < 10⁻¹⁸ — effectively deterministic.
    assert!((10.0..=70.0).contains(&noisy_data));

    let mut laplace_noise_generator = NoiseGenerator::new_with_bounds("Laplace", -10.0, 10.0)?;
    let noisy_data = laplace_noise_generator.apply_on_float(40.0);
    // Wide bounds: Laplace β ≈ 1.01; P(|noise| > 30) < 10⁻¹³ — effectively deterministic.
    assert!((10.0..=70.0).contains(&noisy_data));

    Ok(())
}

#[test]
fn test_noise_uniform_f64() -> Result<(), AnoError> {
    let res = NoiseGenerator::new_with_parameters("Uniform", 0.0, 2.0);
    assert!(res.is_err());

    let mut uniform_noise_generator = NoiseGenerator::new_with_bounds("Uniform", -10.0, 10.0)?;
    let noisy_data = uniform_noise_generator.apply_on_float(40.0);
    assert!((30.0..=50.0).contains(&noisy_data));

    Ok(())
}

#[test]
fn test_noise_gaussian_i64() -> Result<(), AnoError> {
    let mut gaussian_noise_generator = NoiseGenerator::new_with_parameters("Gaussian", 0.0, 1.0)?;
    let noisy_data = gaussian_noise_generator.apply_on_int(40);
    assert!((30..=50).contains(&noisy_data));

    let mut gaussian_noise_generator = NoiseGenerator::new_with_bounds("Gaussian", -5.0, 5.0)?;
    let noisy_data = gaussian_noise_generator.apply_on_int(40);
    assert!((30..=50).contains(&noisy_data));

    Ok(())
}

#[test]
fn test_noise_laplace_i64() -> Result<(), AnoError> {
    let mut laplace_noise_generator = NoiseGenerator::new_with_parameters("Laplace", 0.0, 1.0)?;

    let noisy_data = laplace_noise_generator.apply_on_int(40);
    // Wide bounds: Laplace β ≈ 0.71; P(|noise| > 30) < 10⁻¹⁸ — effectively deterministic.
    assert!((10..=70).contains(&noisy_data));

    let mut laplace_noise_generator = NoiseGenerator::new_with_bounds("Laplace", -10.0, 10.0)?;
    let noisy_data = laplace_noise_generator.apply_on_int(40);
    // Wide bounds: Laplace β ≈ 1.01; P(|noise| > 30) < 10⁻¹³ — effectively deterministic.
    assert!((10..=70).contains(&noisy_data));

    Ok(())
}

#[test]
fn test_noise_uniform_i64() -> Result<(), AnoError> {
    let mut laplace_noise_generator = NoiseGenerator::new_with_bounds("Uniform", -10.0, 10.0)?;
    let noisy_data = laplace_noise_generator.apply_on_int(40);
    assert!((30..=50).contains(&noisy_data));

    Ok(())
}

#[test]
fn test_noise_gaussian_date() -> Result<(), AnoError> {
    let mut gaussian_noise_generator =
        NoiseGenerator::new_with_parameters("Gaussian", 0.0, 2.0 * 3600.0)?;
    let input_datestr = "2023-04-07T12:34:56Z";
    let output_datestr = gaussian_noise_generator.apply_on_date(input_datestr)?;
    let output_date = DateTime::parse_from_rfc3339(&output_datestr)?;

    assert_eq!(output_date.day(), 7);
    assert_eq!(output_date.month(), 4);
    assert_eq!(output_date.year(), 2023);
    // Check that the output date has the same timezone as the input
    assert_eq!(
        output_date.timezone(),
        DateTime::parse_from_rfc3339(input_datestr)?.timezone()
    );

    let res = gaussian_noise_generator.apply_on_date("AAAA");
    assert!(res.is_err());
    Ok(())
}

#[test]
fn test_noise_laplace_date() -> Result<(), AnoError> {
    let mut laplace_noise_generator =
        NoiseGenerator::new_with_parameters("Laplace", 0.0, 2.0 * 3600.0)?;
    let input_datestr = "2023-04-07T12:34:56+05:00";
    let output_datestr = laplace_noise_generator.apply_on_date(input_datestr)?;
    let output_date = DateTime::parse_from_rfc3339(&output_datestr)?;

    assert_eq!(output_date.day(), 7);
    assert_eq!(output_date.month(), 4);
    assert_eq!(output_date.year(), 2023);
    // Check that the output date has the same timezone as the input
    assert_eq!(
        output_date.timezone(),
        DateTime::parse_from_rfc3339(input_datestr)?.timezone()
    );
    Ok(())
}

#[test]
fn test_noise_uniform_date() -> Result<(), AnoError> {
    // generate noise between -10h and +10h
    let mut uniform_noise_generator =
        NoiseGenerator::new_with_bounds("Uniform", -10.0 * 3600.0, 10.0 * 3600.0)?;
    let input_datestr = "2023-04-07T12:34:56-03:00";
    let output_datestr = uniform_noise_generator.apply_on_date(input_datestr)?;
    let output_date = DateTime::parse_from_rfc3339(&output_datestr)?;

    assert_eq!(output_date.day(), 7);
    assert_eq!(output_date.month(), 4);
    assert_eq!(output_date.year(), 2023);
    // Check that the output date has the same timezone as the input
    assert_eq!(
        output_date.timezone(),
        DateTime::parse_from_rfc3339(input_datestr)?.timezone()
    );
    Ok(())
}

#[test]
fn test_mask_word() -> Result<(), AnoError> {
    let input_str = String::from("Confidential: contains -secret- documents");
    let block_words = vec!["confidential", "SECRET"];
    let word_masker = WordMasker::new(&block_words);

    let safe_str = word_masker.apply(&input_str);

    assert_eq!(safe_str, "XXXX: contains -XXXX- documents");
    Ok(())
}

#[test]
fn test_token_word() -> Result<(), AnoError> {
    let input_str = String::from("confidential : contains secret documents with confidential info");
    let block_words = vec!["confidential", "SECRET"];
    let word_tokenizer = WordTokenizer::new(&block_words)?;

    let safe_str = word_tokenizer.apply(&input_str);

    let words: HashSet<&str> = safe_str.split(' ').collect();
    assert!(!words.contains("confidential"));
    assert!(!words.contains("secret"));
    assert!(words.contains("documents"));
    Ok(())
}

#[test]
fn test_word_pattern() -> Result<(), AnoError> {
    let input_str =
        String::from("Confidential: contains -secret- documents with confidential info");
    let pattern = r"-\w+-";
    let pattern_matcher = WordPatternMasker::new(pattern, "####")?;

    let matched_str = pattern_matcher.apply(&input_str);
    assert_eq!(
        matched_str,
        "Confidential: contains #### documents with confidential info"
    );

    let res = WordPatternMasker::new("[", "####");
    assert!(res.is_err());

    Ok(())
}

#[test]
fn test_float_aggregation() -> Result<(), AnoError> {
    let float_aggregator = NumberAggregator::new(-1)?;
    let res = float_aggregator.apply_on_float(1234.567);
    assert_eq!(res, "1234.6");

    let float_aggregator = NumberAggregator::new(2)?;
    let res = float_aggregator.apply_on_float(1234.567);
    assert_eq!(res, "1200");

    let float_aggregator = NumberAggregator::new(10)?;
    let res = float_aggregator.apply_on_float(1234.567);
    assert_eq!(res, "0");

    let float_aggregator = NumberAggregator::new(-10)?;
    let res = float_aggregator.apply_on_float(1234.567);
    assert_eq!(res, "1234.5670000000");

    let res = NumberAggregator::new(309);
    assert!(res.is_err());

    Ok(())
}

#[test]
fn test_int_aggregation() -> Result<(), AnoError> {
    let int_aggregator = NumberAggregator::new(2)?;
    let res = int_aggregator.apply_on_int(1234);
    assert_eq!(res, "1200");

    let int_aggregator = NumberAggregator::new(-2)?;
    let res = int_aggregator.apply_on_int(1234);
    assert_eq!(res, "1234");

    Ok(())
}

#[test]
fn test_time_aggregation() -> Result<(), AnoError> {
    let time_aggregator = DateAggregator::new(TimeUnit::Hour);
    let input_datestr = "2023-04-07T12:34:56+02:00";
    let output_datestr = time_aggregator.apply_on_date(input_datestr)?;
    let output_date = DateTime::parse_from_rfc3339(&output_datestr)?;

    assert_eq!(output_date.day(), 7);
    assert_eq!(output_date.month(), 4);
    assert_eq!(output_date.year(), 2023);

    assert_eq!(output_date.hour(), 12);
    assert_eq!(output_date.minute(), 0);
    assert_eq!(output_date.second(), 0);

    // Check that the output date has the same timezone as the input
    assert_eq!(
        output_date.timezone(),
        DateTime::parse_from_rfc3339(input_datestr)?.timezone()
    );

    let res = time_aggregator.apply_on_date("AAAA");
    assert!(res.is_err());

    Ok(())
}

#[test]
fn test_date_aggregation() -> Result<(), AnoError> {
    let date_aggregator = DateAggregator::new(TimeUnit::Month);
    let input_datestr = "2023-04-07T12:34:56-05:00";
    let output_datestr = date_aggregator.apply_on_date(input_datestr)?;
    let output_date = DateTime::parse_from_rfc3339(&output_datestr)?;

    assert_eq!(output_date.day(), 1);
    assert_eq!(output_date.month(), 4);
    assert_eq!(output_date.year(), 2023);

    assert_eq!(output_date.hour(), 0);
    assert_eq!(output_date.minute(), 0);
    assert_eq!(output_date.second(), 0);

    // Check that the output date has the same timezone as the input
    assert_eq!(
        output_date.timezone(),
        DateTime::parse_from_rfc3339(input_datestr)?.timezone()
    );

    Ok(())
}

#[test]
fn test_float_scale() -> Result<(), AnoError> {
    let float_scaler = NumberScaler::new(10.0, 5.0, 2.0, -50.0)?;

    let n1 = float_scaler.apply_on_float(20.0);
    let n2 = float_scaler.apply_on_float(19.5);

    assert!(n1 > n2);
    Ok(())
}

#[test]
fn test_int_scale() -> Result<(), AnoError> {
    let int_scaler = NumberScaler::new(10.0, 5.0, 20.0, -50.0)?;

    let n1 = int_scaler.apply_on_int(20);
    let n2 = int_scaler.apply_on_int(19);

    assert!(n1 >= n2);
    Ok(())
}

#[test]
fn test_number_scaler_zero_std_deviation() {
    let res = NumberScaler::new(10.0, 0.0, 2.0, -50.0);
    assert!(res.is_err());
}

#[test]
fn test_noise_nan_inf_input() -> Result<(), AnoError> {
    let mut noise_gen = NoiseGenerator::new_with_parameters("Gaussian", 0.0, 1.0)?;
    // NaN propagates: NaN + any_finite = NaN
    assert!(noise_gen.apply_on_float(f64::NAN).is_nan());
    // Infinity propagates: Inf + any_finite = Inf
    assert!(noise_gen.apply_on_float(f64::INFINITY).is_infinite());
    Ok(())
}
