# Anonymization

Cosmian KMS exposes a set of data anonymization methods through a dedicated REST endpoint. These methods are stateless, require no cryptographic key, and are available under `/tokenize/{method}` on any KMS instance built with the `non-fips` feature.

All endpoints accept a JSON body and return a JSON object with a single `result` field. Errors come back as HTTP 422 with `{ "code": 422, "message": "..." }`.

The `ckms tokenize` CLI command wraps each of these endpoints if you prefer working from the command line.

[TOC]

## Endpoints

### Hash

`POST /tokenize/hash`

Produces an irreversible, base64-encoded hash of a string. Three algorithms are available: `SHA2` (SHA-256), `SHA3` (SHA3-256), and `Argon2`. A salt can be passed as a base64-encoded byte string; for Argon2 it is required.

```json
{
  "data": "test sha2",
  "method": "SHA2"
}
```

Response:

```json
{ "result": "Px0txVYqBePXWF5K4xFn0Pa2mhnYA/jfsLtpIF70vJ8=" }
```

Use Argon2 when the input has low entropy (passwords, short identifiers) and you need resistance to brute-force lookup. Use SHA2 or SHA3 for high-entropy values or when throughput matters.

### Noise

`POST /tokenize/noise`

Adds random noise to a numeric or date value. Three distributions are supported: `Gaussian`, `Laplace`, and `Uniform`. You can parameterize the distribution either by mean and standard deviation, or by lower and upper bounds.

The `data_type` field controls what kind of input to expect: `float`, `integer`, or `date`. Dates must be in RFC 3339 format (`2023-04-07T12:34:56Z`); the timezone is preserved in the output.

```json
{
  "data": 42000.0,
  "data_type": "float",
  "method": "Laplace",
  "mean": 0.0,
  "std_dev": 500.0
}
```

```json
{
  "data": "2023-04-07T12:34:56+02:00",
  "data_type": "date",
  "method": "Uniform",
  "min_bound": -3600.0,
  "max_bound": 3600.0
}
```

Laplace noise is the standard choice for differential privacy budgets. Uniform noise is appropriate when you need a hard bound on the perturbation. Gaussian is a reasonable default for datasets where outliers are acceptable.

### Word Mask

`POST /tokenize/word-mask`

Replaces every occurrence of a listed word with `XXXX`, case-insensitively, matching only on word boundaries.

```json
{
  "data": "Confidential: contains -secret- documents",
  "words": ["confidential", "secret"]
}
```

```json
{ "result": "XXXX: contains -XXXX- documents" }
```

Non-word characters surrounding a target word (dashes, punctuation, spaces) are preserved.

### Word Tokenize

`POST /tokenize/word-tokenize`

Replaces listed words with random 16-byte hex tokens. All occurrences of the same word receive the same token within a single request, so joins across a single document remain consistent. Across separate requests, the tokens are different.

```json
{
  "data": "confidential meeting with confidential sources",
  "words": ["confidential"]
}
```

The output might be:

```json
{ "result": "3A9F1C8B2E7D4A60 meeting with 3A9F1C8B2E7D4A60 sources" }
```

### Word Pattern Mask

`POST /tokenize/word-pattern-mask`

Replaces all substrings matching a regular expression with a fixed replacement string. The pattern is limited to 1024 characters.

```json
{
  "data": "Call me at +33 6 12 34 56 78 or +1-555-123-4567",
  "pattern": "\\+[\\d\\s\\-]+",
  "replace": "[PHONE]"
}
```

```json
{ "result": "Call me at [PHONE]or [PHONE]" }
```

### Aggregate Number

`POST /tokenize/aggregate-number`

Rounds a number to the nearest power of ten. `power_of_ten: 2` rounds to the nearest hundred; `power_of_ten: -1` keeps one decimal place.

```json
{
  "data": 1234567,
  "data_type": "integer",
  "power_of_ten": 3
}
```

```json
{ "result": "1235000" }
```

`data_type` is either `float` or `integer`.

### Aggregate Date

`POST /tokenize/aggregate-date`

Truncates a date to the specified precision. The `time_unit` field accepts `Second`, `Minute`, `Hour`, `Day`, `Month`, or `Year`. The timezone offset is preserved.

```json
{
  "data": "2023-04-07T12:34:56+02:00",
  "time_unit": "Month"
}
```

```json
{ "result": "2023-04-01T00:00:00+02:00" }
```

### Scale Number

`POST /tokenize/scale-number`

Applies a z-score normalization followed by a linear transformation. Given the mean and standard deviation of the original distribution, each value is standardized to zero mean and unit variance, then multiplied by `scale` and shifted by `translate`.

```json
{
  "data": 75.0,
  "data_type": "float",
  "mean": 50.0,
  "std_deviation": 15.0,
  "scale": 10.0,
  "translate": 100.0
}
```

```json
{ "result": 116.6666666666667 }
```

`data_type` is either `float` or `integer`. For integers the result is rounded to the nearest integer.

## Relation to Format-Preserving Encryption

The methods above are one-way or statistically approximate transformations. They do not require a key and cannot be reversed to recover the original value.

For reversible, key-based field-level encryption that preserves the format of the original value (digit strings stay digit strings, alphanumeric stays alphanumeric), see [Format-Preserving Encryption (FPE FF1)](../certifications_and_compliance/cryptographic_algorithms/algorithms.md#fpe-ff1). FPE is accessed through the KMIP Encrypt and Decrypt operations, not through the `/tokenize` endpoint.

| Property | Anonymization (`/tokenize`) | FPE (KMIP) |
|---|---|---|
| Reversible | No | Yes |
| Requires a key | No | Yes (256-bit AES) |
| Format-preserving | Partial (noise, rounding) | Exact |
| FIPS mode | No | No |
| Use case | Analytics, data sharing | Tokenized storage, round-trip |
