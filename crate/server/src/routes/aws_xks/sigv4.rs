//! AWS Signature Version 4 verifier for the AWS XKS proxy.
//!
//! Only header authentication (`Authorization: AWS4-HMAC-SHA256 ...`) is accepted; query-string
//! (presigned URL) authentication is rejected. Timestamp freshness is enforced by the caller.
//!
//! Spec: <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv4-create-signed-request.html>.
//! The URI path is normalized (`//`, `.` and `..` removed) and percent-encoded once, as the AWS
//! `SigV4` test suite expects; this is the behavior of the previously used validator.

use actix_web::web::Bytes;
use openssl::{
    error::ErrorStack, hash::MessageDigest, memcmp, pkey::PKey, sha::sha256, sign::Signer,
};
use time::{
    OffsetDateTime, PrimitiveDateTime, format_description::BorrowedFormatItem,
    macros::format_description,
};
use zeroize::Zeroizing;

use super::AwsXksParams;
use crate::routes::enrollment::secrets_equal;

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const SCOPE_TERMINATOR: &str = "aws4_request";
const X_AMZ_DATE: &str = "x-amz-date";
const X_AMZ_CONTENT_SHA256: &str = "x-amz-content-sha256";

/// Basic ISO 8601 timestamp used by `SigV4`: `YYYYMMDD'T'HHMMSS'Z'`.
const TIMESTAMP_FORMAT: &[BorrowedFormatItem<'static>] =
    format_description!("[year][month][day]T[hour][minute][second]Z");
const DATE_FORMAT: &[BorrowedFormatItem<'static>] = format_description!("[year][month][day]");

/// Parses a `SigV4` timestamp (`YYYYMMDD'T'HHMMSS'Z'`, always UTC).
pub(super) fn parse_sigv4_timestamp(timestamp: &str) -> Result<OffsetDateTime, time::error::Parse> {
    PrimitiveDateTime::parse(timestamp, TIMESTAMP_FORMAT).map(PrimitiveDateTime::assume_utc)
}

/// Verifies the `SigV4` `Authorization` header of `request` against the XKS credentials, region
/// and service in `params`.
///
/// The returned error explains the rejection; it never contains secret material or the expected
/// signature.
pub(super) fn verify_sigv4_request(
    request: &http::Request<Bytes>,
    params: &AwsXksParams,
) -> Result<(), String> {
    let headers = request.headers();
    // A second copy could be the one a fronting proxy honours: refuse to pick between them.
    if headers.get_all(http::header::AUTHORIZATION).iter().count() > 1 {
        return Err("multiple Authorization headers".to_owned());
    }
    let authorization = headers
        .get(http::header::AUTHORIZATION)
        .ok_or("missing Authorization header (query-string authentication is not supported)")?
        .to_str()
        .map_err(|e| format!("invalid Authorization header encoding: {e}"))?
        .trim_ascii();

    let (algorithm, parameters) = authorization.split_once(' ').unwrap_or((authorization, ""));
    if algorithm != ALGORITHM {
        return Err(format!("unsupported algorithm, expected {ALGORITHM}"));
    }

    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for parameter in parameters
        .split(',')
        .map(str::trim_ascii)
        .filter(|p| !p.is_empty())
    {
        let (name, value) = parameter
            .split_once('=')
            .ok_or("malformed Authorization parameter (missing '=')")?;
        let slot = match name {
            "Credential" => &mut credential,
            "SignedHeaders" => &mut signed_headers,
            "Signature" => &mut signature,
            _ => continue,
        };
        if slot.replace(value).is_some() {
            return Err(format!("duplicate Authorization parameter {name}"));
        }
    }
    let credential = credential.ok_or("Authorization header requires 'Credential'")?;
    let signed_headers = signed_headers.ok_or("Authorization header requires 'SignedHeaders'")?;
    let signature = signature.ok_or("Authorization header requires 'Signature'")?;

    // Same precedence as the freshness check: `X-Amz-Date`, then `Date`.
    let timestamp = headers
        .get(X_AMZ_DATE)
        .or_else(|| headers.get(http::header::DATE))
        .ok_or("missing X-Amz-Date or Date header")?
        .to_str()
        .map_err(|e| format!("invalid request timestamp encoding: {e}"))?;
    let timestamp =
        parse_sigv4_timestamp(timestamp).map_err(|e| format!("invalid request timestamp: {e}"))?;
    let timestamp_str = timestamp
        .format(TIMESTAMP_FORMAT)
        .map_err(|e| format!("cannot format request timestamp: {e}"))?;
    let date = timestamp
        .format(DATE_FORMAT)
        .map_err(|e| format!("cannot format request date: {e}"))?;

    let [
        access_key_id,
        scope_date,
        scope_region,
        scope_service,
        scope_terminator,
    ] = <[&str; 5]>::try_from(credential.split('/').collect::<Vec<_>>()).map_err(|parts| {
        format!(
            "Credential must have 5 slash-separated elements, got {}",
            parts.len()
        )
    })?;
    if !secrets_equal(access_key_id, &params.sigv4_access_key_id) {
        return Err("unknown access key id".to_owned());
    }
    if scope_date != date {
        return Err("credential scope date does not match the request timestamp date".to_owned());
    }
    if scope_region != params.region {
        return Err("credential scope region does not match the configured region".to_owned());
    }
    if scope_service != params.service {
        return Err("credential scope service does not match the configured service".to_owned());
    }
    if scope_terminator != SCOPE_TERMINATOR {
        return Err(format!("credential scope must end with {SCOPE_TERMINATOR}"));
    }

    let mut signed_headers: Vec<&str> = signed_headers.split(';').collect();
    signed_headers.sort_unstable();
    let signed_header_count = signed_headers.len();
    signed_headers.dedup();
    if signed_headers.len() != signed_header_count {
        return Err("SignedHeaders contains duplicate entries".to_owned());
    }
    if !signed_headers.contains(&"host") {
        return Err("'host' must be a signed header".to_owned());
    }
    if headers.contains_key(X_AMZ_DATE) && !signed_headers.contains(&X_AMZ_DATE) {
        return Err("'x-amz-date' must be a signed header".to_owned());
    }

    let payload_hash = hex::encode(sha256(request.body()));
    // Rejects `UNSIGNED-PAYLOAD`, streaming payloads and hashes of another body.
    if let Some(declared) = headers.get(X_AMZ_CONTENT_SHA256)
        && declared.as_bytes() != payload_hash.as_bytes()
    {
        return Err(
            "x-amz-content-sha256 does not match the SHA-256 of the request body".to_owned(),
        );
    }

    let canonical_request = canonical_request(request, &signed_headers, &payload_hash)?;
    let string_to_sign = format!(
        "{ALGORITHM}\n{timestamp_str}\n{date}/{}/{}/{SCOPE_TERMINATOR}\n{}",
        params.region,
        params.service,
        hex::encode(sha256(&canonical_request))
    );
    let signing_key = derive_signing_key(
        &params.sigv4_secret_access_key,
        &date,
        &params.region,
        &params.service,
    )
    .map_err(|e| format!("cannot derive the signing key: {e}"))?;
    let expected = hmac_sha256(signing_key.as_slice(), string_to_sign.as_bytes())
        .map_err(|e| format!("cannot compute the signature: {e}"))?;

    let mut provided = [0_u8; 32];
    hex::decode_to_slice(signature, &mut provided)
        .map_err(|e| format!("Signature is not a hex-encoded SHA-256 HMAC: {e}"))?;
    if !memcmp::eq(&provided, expected.as_slice()) {
        return Err("signature does not match".to_owned());
    }
    Ok(())
}

/// Builds the `SigV4` canonical request; `signed_headers` must be sorted and deduplicated.
fn canonical_request(
    request: &http::Request<Bytes>,
    signed_headers: &[&str],
    payload_hash: &str,
) -> Result<Vec<u8>, String> {
    let mut canonical = Vec::with_capacity(512);
    canonical.extend_from_slice(request.method().as_str().as_bytes());
    canonical.push(b'\n');
    canonical.extend_from_slice(canonical_uri_path(request.uri().path())?.as_bytes());
    canonical.push(b'\n');
    canonical.extend_from_slice(
        canonical_query_string(request.uri().query().unwrap_or_default())?.as_bytes(),
    );
    canonical.push(b'\n');
    for name in signed_headers {
        if name.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(format!("signed header name '{name}' is not lowercase"));
        }
        let mut values = request.headers().get_all(*name).iter().peekable();
        if values.peek().is_none() {
            return Err(format!(
                "signed header '{name}' is missing from the request"
            ));
        }
        canonical.extend_from_slice(name.as_bytes());
        canonical.push(b':');
        for (index, value) in values.enumerate() {
            if index > 0 {
                canonical.push(b',');
            }
            // Trim and collapse runs of spaces.
            for (word_index, word) in value
                .as_bytes()
                .split(|b| *b == b' ')
                .filter(|w| !w.is_empty())
                .enumerate()
            {
                if word_index > 0 {
                    canonical.push(b' ');
                }
                canonical.extend_from_slice(word);
            }
        }
        canonical.push(b'\n');
    }
    canonical.push(b'\n');
    canonical.extend_from_slice(signed_headers.join(";").as_bytes());
    canonical.push(b'\n');
    canonical.extend_from_slice(payload_hash.as_bytes());
    Ok(canonical)
}

/// Normalizes the URI path: empty segments from `//` runs, `.` and `..` are removed (a trailing
/// slash is kept) and every segment is percent-encoded once.
fn canonical_uri_path(path: &str) -> Result<String, String> {
    if path.is_empty() {
        return Ok("/".to_owned());
    }
    if !path.starts_with('/') {
        return Err("URI path is not absolute".to_owned());
    }
    let mut segments: Vec<String> = Vec::new();
    let mut raw_segments = path.split('/').skip(1).peekable();
    while let Some(raw) = raw_segments.next() {
        if raw.is_empty() && raw_segments.peek().is_some() {
            continue;
        }
        let segment = normalize_uri_component(raw)?;
        match segment.as_str() {
            "." => {}
            ".." => {
                if segments.pop().is_none() {
                    return Err("URI path navigates above the root".to_owned());
                }
            }
            _ => segments.push(segment),
        }
    }
    Ok(format!("/{}", segments.join("/")))
}

/// Sorts the query parameters by encoded name, then encoded value.
fn canonical_query_string(query: &str) -> Result<String, String> {
    let mut parameters = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|parameter| {
            let (name, value) = parameter.split_once('=').unwrap_or((parameter, ""));
            Ok((
                normalize_uri_component(name)?,
                normalize_uri_component(value)?,
            ))
        })
        .collect::<Result<Vec<(String, String)>, String>>()?;
    parameters.sort_unstable();
    Ok(parameters
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&"))
}

/// RFC 3986 encoding of a path segment or query element: unreserved characters stay literal,
/// existing escapes are decoded then re-encoded with uppercase hex, and `+` is read as a space.
fn normalize_uri_component(component: &str) -> Result<String, String> {
    let bytes = component.as_bytes();
    let mut normalized = String::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        let decoded = match byte {
            b'%' => {
                let escape = bytes
                    .get(index + 1..index + 3)
                    .ok_or("incomplete percent-encoding in URI")?;
                let mut value = [0_u8; 1];
                hex::decode_to_slice(escape, &mut value)
                    .map_err(|e| format!("invalid percent-encoding in URI: {e}"))?;
                index += 3;
                let [value] = value;
                value
            }
            b'+' => {
                index += 1;
                b' '
            }
            _ => {
                index += 1;
                byte
            }
        };
        if decoded.is_ascii_alphanumeric() || matches!(decoded, b'-' | b'.' | b'_' | b'~') {
            normalized.push(char::from(decoded));
        } else {
            normalized.push('%');
            normalized.push_str(&hex::encode_upper([decoded]));
        }
    }
    Ok(normalized)
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<Zeroizing<[u8; 32]>, ErrorStack> {
    let key = PKey::hmac(key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
    signer.update(message)?;
    let mut mac = Zeroizing::new([0_u8; 32]);
    signer.sign(mac.as_mut_slice())?;
    Ok(mac)
}

/// Derives the `SigV4` `kSigning` key for `date` (`YYYYMMDD`); accepts any secret length, so the
/// full 43–64 character XKS range is supported.
fn derive_signing_key(
    secret: &str,
    date: &str,
    region: &str,
    service: &str,
) -> Result<Zeroizing<[u8; 32]>, ErrorStack> {
    let k_secret = Zeroizing::new(format!("AWS4{secret}"));
    let k_date = hmac_sha256(k_secret.as_bytes(), date.as_bytes())?;
    let k_region = hmac_sha256(k_date.as_slice(), region.as_bytes())?;
    let k_service = hmac_sha256(k_region.as_slice(), service.as_bytes())?;
    hmac_sha256(k_service.as_slice(), SCOPE_TERMINATOR.as_bytes())
}

#[cfg(test)]
mod tests {
    //! Vectors marked "AWS" come from the AWS `SigV4` test suite (`aws-sig-v4-test-suite`, as
    //! shipped with the `AWS4-HMAC-SHA256` docs and mirrored in `awslabs/aws-c-auth`); all others
    //! encode this module's own expectations.

    use super::*;

    const AWS_DATE: &str = "20150830T123600Z";
    const AWS_HOST: &str = "example.amazonaws.com";
    const VANILLA_SIGNATURE: &str =
        "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31";
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn aws_params() -> AwsXksParams {
        AwsXksParams {
            region: "us-east-1".to_owned(),
            service: "service".to_owned(),
            sigv4_access_key_id: "AKIDEXAMPLE".to_owned(),
            sigv4_secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned(),
        }
    }

    fn authorization(signed_headers: &str, signature: &str) -> String {
        format!(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders={signed_headers}, Signature={signature}"
        )
    }

    /// Request with the AWS test-suite `Host` and `X-Amz-Date`, `extra` headers and `authorization`.
    fn aws_request(
        method: &str,
        uri: &str,
        extra: &[(&str, &str)],
        authorization: Option<&str>,
        body: &'static [u8],
    ) -> http::Request<Bytes> {
        let mut builder = http::Request::builder()
            .method(method)
            .uri(uri)
            .header("Host", AWS_HOST)
            .header("X-Amz-Date", AWS_DATE);
        for (name, value) in extra {
            builder = builder.header(*name, *value);
        }
        if let Some(authorization) = authorization {
            builder = builder.header("Authorization", authorization);
        }
        builder
            .body(Bytes::from_static(body))
            .expect("valid test request")
    }

    fn vanilla(authorization: &str) -> http::Request<Bytes> {
        aws_request("GET", "/", &[], Some(authorization), b"")
    }

    fn vanilla_authorization() -> String {
        authorization("host;x-amz-date", VANILLA_SIGNATURE)
    }

    fn rejection(request: &http::Request<Bytes>, params: &AwsXksParams) -> String {
        verify_sigv4_request(request, params).expect_err("request must be rejected")
    }

    /// AWS published `SigV4` example (docs: "Examples of how to derive a signing key").
    #[test]
    fn derive_signing_key_matches_aws_example() {
        let key = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20120215",
            "us-east-1",
            "iam",
        )
        .expect("derive signing key");
        assert_eq!(
            hex::encode(key.as_slice()),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
    }

    /// AWS `get-vanilla`: canonical request, its hash (from `get-vanilla.sts`) and signature.
    #[test]
    fn get_vanilla_canonical_request_and_signature() {
        let request = vanilla(&vanilla_authorization());
        let canonical = canonical_request(&request, &["host", "x-amz-date"], EMPTY_SHA256)
            .expect("canonical request");
        assert_eq!(
            String::from_utf8_lossy(&canonical),
            format!(
                "GET\n/\n\nhost:{AWS_HOST}\nx-amz-date:{AWS_DATE}\n\nhost;x-amz-date\n{EMPTY_SHA256}"
            )
        );
        assert_eq!(
            hex::encode(sha256(&canonical)),
            "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
        );
        assert_eq!(verify_sigv4_request(&request, &aws_params()), Ok(()));
    }

    /// One AWS test-suite vector: name, method, URI, extra headers, `SignedHeaders`, signature.
    type AwsVector<'a> = (
        &'a str,
        &'a str,
        &'a str,
        &'a [(&'a str, &'a str)],
        &'a str,
        &'a str,
    );

    /// AWS test-suite vectors (name, method, URI, extra headers, `SignedHeaders`, signature).
    #[test]
    fn aws_test_suite_vectors_verify() {
        let cases: [AwsVector<'_>; 15] = [
            (
                "get-vanilla",
                "GET",
                "/",
                &[],
                "host;x-amz-date",
                VANILLA_SIGNATURE,
            ),
            (
                "post-vanilla",
                "POST",
                "/",
                &[],
                "host;x-amz-date",
                "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b",
            ),
            (
                "post-vanilla-query",
                "POST",
                "/?Param1=value1",
                &[],
                "host;x-amz-date",
                "28038455d6de14eafc1f9222cf5aa6f1a96197d7deb8263271d420d138af7f11",
            ),
            (
                "get-vanilla-query-order-key-case (unsorted keys)",
                "GET",
                "/?Param2=value2&Param1=value1",
                &[],
                "host;x-amz-date",
                "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500",
            ),
            (
                "get-vanilla-query-order-value (duplicate key, unsorted values)",
                "GET",
                "/?Param1=value2&Param1=value1",
                &[],
                "host;x-amz-date",
                "5772eed61e12b33fae39ee5e7012498b51d56abc0abb7c60486157bd471c4694",
            ),
            (
                "get-vanilla-query-unreserved",
                "GET",
                "/?-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                &[],
                "host;x-amz-date",
                "9c3e54bfcdf0b19771a7f523ee5669cdf59bc7cc0884027167c21bb143a40197",
            ),
            (
                "get-vanilla-utf8-query (percent-encoded on the wire)",
                "GET",
                "/?%E1%88%B4=bar",
                &[],
                "host;x-amz-date",
                "2cdec8eed098649ff3a119c94853b13c643bcf08f8b0a1d91e12c9027818dd04",
            ),
            (
                "get-unreserved",
                "GET",
                "/-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                &[],
                "host;x-amz-date",
                "07ef7494c76fa4850883e2b006601f940f8a34d404d0cfa977f52a65bbf5f24f",
            ),
            (
                "get-utf8 (percent-encoded on the wire)",
                "GET",
                "/%E1%88%B4",
                &[],
                "host;x-amz-date",
                "8318018e0b0f223aa2bbf98705b62bb787dc9c0e678f255a891fd03141be5d85",
            ),
            (
                "normalize-path/get-space (percent-encoded on the wire)",
                "GET",
                "/example%20space/",
                &[],
                "host;x-amz-date",
                "652487583200325589f1fba4c7e578f72c47cb61beeca81406b39ddec1366741",
            ),
            (
                "normalize-path/get-slashes",
                "GET",
                "//example//",
                &[],
                "host;x-amz-date",
                "9a624bd73a37c9a373b5312afbebe7a714a789de108f0bdfe846570885f57e84",
            ),
            (
                "normalize-path/get-relative-relative",
                "GET",
                "/example1/example2/../..",
                &[],
                "host;x-amz-date",
                VANILLA_SIGNATURE,
            ),
            (
                "normalize-path/get-slash-pointless-dot",
                "GET",
                "/./example",
                &[],
                "host;x-amz-date",
                "ef75d96142cf21edca26f06005da7988e4f8dc83a165a80865db7089db637ec5",
            ),
            (
                "get-header-value-trim",
                "GET",
                "/",
                &[("My-Header1", "value1"), ("My-Header2", "\"a   b   c\"")],
                "host;my-header1;my-header2;x-amz-date",
                "acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736",
            ),
            (
                "get-header-value-order (multi-value header)",
                "GET",
                "/",
                &[
                    ("My-Header1", "value4"),
                    ("My-Header1", "value1"),
                    ("My-Header1", "value3"),
                    ("My-Header1", "value2"),
                ],
                "host;my-header1;x-amz-date",
                "08c7e5a9acfcfeb3ab6b2185e75ce8b1deb5e634ec47601a50643f830c755c01",
            ),
        ];
        for (name, method, uri, extra, signed_headers, signature) in cases {
            let request = aws_request(
                method,
                uri,
                extra,
                Some(&authorization(signed_headers, signature)),
                b"",
            );
            assert_eq!(
                verify_sigv4_request(&request, &aws_params()),
                Ok(()),
                "{name}"
            );
        }
    }

    /// AWS `normalize-path/get-slash-dot-slash` and `get-slash` both canonicalize to `/`.
    #[test]
    fn aws_dot_and_slash_paths_canonicalize_to_root() {
        for path in ["/./", "//", "/example/.."] {
            assert_eq!(canonical_uri_path(path), Ok("/".to_owned()), "{path}");
            assert_eq!(
                verify_sigv4_request(
                    &aws_request("GET", path, &[], Some(&vanilla_authorization()), b""),
                    &aws_params()
                ),
                Ok(()),
                "{path}"
            );
        }
    }

    const FORM_BODY: &[u8] = b"Param1=value1";
    const FORM_BODY_SHA256: &str =
        "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e";
    const FORM_SIGNED_HEADERS: &str =
        "content-length;content-type;host;x-amz-content-sha256;x-amz-date";

    fn form_request(body: &'static [u8], content_sha256: &str) -> http::Request<Bytes> {
        aws_request(
            "POST",
            "/",
            &[
                ("Content-Length", "13"),
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("X-Amz-Content-Sha256", content_sha256),
            ],
            Some(&authorization(
                FORM_SIGNED_HEADERS,
                "d3875051da38690788ef43de4db0d8f280229d82040bfac253562e56c3f20e0b",
            )),
            body,
        )
    }

    /// AWS (`aws-c-auth` suite) `post-x-www-form-urlencoded` with `sign_body`: a POST with a body.
    #[test]
    fn aws_post_with_body_verifies() {
        assert_eq!(hex::encode(sha256(FORM_BODY)), FORM_BODY_SHA256);
        assert_eq!(
            verify_sigv4_request(&form_request(FORM_BODY, FORM_BODY_SHA256), &aws_params()),
            Ok(())
        );
    }

    #[test]
    fn tampered_body_is_rejected() {
        // Same length, so only the payload hash changes.
        let error = rejection(
            &form_request(b"Param1=value2", FORM_BODY_SHA256),
            &aws_params(),
        );
        assert!(error.contains("x-amz-content-sha256"), "{error}");

        // Without `x-amz-content-sha256` the body still feeds the canonical request.
        let request = aws_request(
            "POST",
            "/",
            &[],
            Some(&authorization(
                "host;x-amz-date",
                "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b",
            )),
            b"tampered",
        );
        let error = rejection(&request, &aws_params());
        assert_eq!(error, "signature does not match");
    }

    #[test]
    fn content_sha256_header_must_match_body() {
        let unsigned_header = |value: &str| {
            aws_request(
                "GET",
                "/",
                &[("X-Amz-Content-Sha256", value)],
                Some(&vanilla_authorization()),
                b"",
            )
        };
        assert_eq!(
            verify_sigv4_request(&unsigned_header(EMPTY_SHA256), &aws_params()),
            Ok(())
        );
        for value in [
            "UNSIGNED-PAYLOAD",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            FORM_BODY_SHA256,
        ] {
            let error = rejection(&unsigned_header(value), &aws_params());
            assert!(error.contains("x-amz-content-sha256"), "{value}: {error}");
        }
    }

    #[test]
    fn tampered_signed_header_value_is_rejected() {
        let request = aws_request(
            "GET",
            "/",
            &[("My-Header1", "value2"), ("My-Header2", "\"a b c\"")],
            Some(&authorization(
                "host;my-header1;my-header2;x-amz-date",
                "acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736",
            )),
            b"",
        );
        assert_eq!(
            rejection(&request, &aws_params()),
            "signature does not match"
        );
    }

    #[test]
    fn tampered_query_or_path_is_rejected() {
        // Signed for `/?Param1=value2&Param1=value1` (AWS `get-vanilla-query-order-value`).
        for uri in [
            "/?Param1=value1&Param1=value3",
            "/example?Param1=value2&Param1=value1",
        ] {
            let request = aws_request(
                "GET",
                uri,
                &[],
                Some(&authorization(
                    "host;x-amz-date",
                    "5772eed61e12b33fae39ee5e7012498b51d56abc0abb7c60486157bd471c4694",
                )),
                b"",
            );
            assert_eq!(
                rejection(&request, &aws_params()),
                "signature does not match",
                "{uri}"
            );
        }
    }

    #[test]
    fn wrong_signature_is_rejected() {
        let mut signature = VANILLA_SIGNATURE.to_owned();
        signature.replace_range(0..1, "6");
        let error = rejection(
            &vanilla(&authorization("host;x-amz-date", &signature)),
            &aws_params(),
        );
        assert_eq!(error, "signature does not match");
    }

    #[test]
    fn signature_hex_is_case_insensitive_and_length_checked() {
        let upper = vanilla(&authorization(
            "host;x-amz-date",
            &VANILLA_SIGNATURE.to_ascii_uppercase(),
        ));
        assert_eq!(verify_sigv4_request(&upper, &aws_params()), Ok(()));

        let too_short = &VANILLA_SIGNATURE[..62];
        let too_long = format!("{VANILLA_SIGNATURE}00");
        let not_hex = format!("zz{}", &VANILLA_SIGNATURE[2..]);
        for signature in [too_short, too_long.as_str(), not_hex.as_str(), ""] {
            let error = rejection(
                &vanilla(&authorization("host;x-amz-date", signature)),
                &aws_params(),
            );
            assert!(error.contains("not a hex-encoded"), "{signature}: {error}");
        }
    }

    #[test]
    fn wrong_scope_is_rejected() {
        let mut params = aws_params();
        params.region = "us-west-2".to_owned();
        assert!(rejection(&vanilla(&vanilla_authorization()), &params).contains("region"));

        let mut params = aws_params();
        params.service = "kms".to_owned();
        assert!(rejection(&vanilla(&vanilla_authorization()), &params).contains("service"));

        let wrong_date = vanilla_authorization().replace("/20150830/", "/20150831/");
        assert!(rejection(&vanilla(&wrong_date), &aws_params()).contains("date"));

        let wrong_terminator = vanilla_authorization().replace("aws4_request", "invalid_scope");
        assert!(rejection(&vanilla(&wrong_terminator), &aws_params()).contains("aws4_request"));

        let short = vanilla_authorization().replace("/aws4_request", "");
        assert!(rejection(&vanilla(&short), &aws_params()).contains("5 slash-separated"));
    }

    #[test]
    fn unknown_access_key_id_is_rejected() {
        let mut params = aws_params();
        params.sigv4_access_key_id = "AKIDOTHER".to_owned();
        assert_eq!(
            rejection(&vanilla(&vanilla_authorization()), &params),
            "unknown access key id"
        );
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let mut params = aws_params();
        params.sigv4_secret_access_key = "x".repeat(43);
        assert_eq!(
            rejection(&vanilla(&vanilla_authorization()), &params),
            "signature does not match"
        );
    }

    #[test]
    fn signed_headers_requirements() {
        let missing_host = vanilla(&authorization("x-amz-date", VANILLA_SIGNATURE));
        assert!(rejection(&missing_host, &aws_params()).contains("'host'"));

        let missing_date = vanilla(&authorization("host", VANILLA_SIGNATURE));
        assert!(rejection(&missing_date, &aws_params()).contains("'x-amz-date'"));

        let duplicate = vanilla(&authorization("host;host;x-amz-date", VANILLA_SIGNATURE));
        assert!(rejection(&duplicate, &aws_params()).contains("duplicate"));

        let absent = vanilla(&authorization(
            "host;my-header;x-amz-date",
            VANILLA_SIGNATURE,
        ));
        assert!(rejection(&absent, &aws_params()).contains("missing from the request"));

        let uppercase = vanilla(&authorization("Host;host;x-amz-date", VANILLA_SIGNATURE));
        assert!(rejection(&uppercase, &aws_params()).contains("not lowercase"));

        // Unsorted SignedHeaders are canonicalized in sorted order, as the previous validator did.
        let unsorted = vanilla(&authorization("x-amz-date;host", VANILLA_SIGNATURE));
        assert_eq!(verify_sigv4_request(&unsorted, &aws_params()), Ok(()));
    }

    #[test]
    fn malformed_authorization_is_rejected() {
        let no_authorization = aws_request("GET", "/", &[], None, b"");
        assert!(rejection(&no_authorization, &aws_params()).contains("missing Authorization"));

        // Presigned (query-string) authentication is not supported.
        let presigned = aws_request(
            "GET",
            "/?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fservice%2Faws4_request&X-Amz-SignedHeaders=host&X-Amz-Signature=00",
            &[],
            None,
            b"",
        );
        assert!(rejection(&presigned, &aws_params()).contains("missing Authorization"));

        let wrong_algorithm =
            vanilla_authorization().replace("AWS4-HMAC-SHA256", "AWS4-HMAC-SHA512");
        assert!(
            rejection(&vanilla(&wrong_algorithm), &aws_params()).contains("unsupported algorithm")
        );

        let duplicate = format!("{}, Signature={VANILLA_SIGNATURE}", vanilla_authorization());
        assert!(rejection(&vanilla(&duplicate), &aws_params()).contains("duplicate"));

        let missing_signature =
            vanilla_authorization().replace(&format!(", Signature={VANILLA_SIGNATURE}"), "");
        assert!(rejection(&vanilla(&missing_signature), &aws_params()).contains("'Signature'"));

        let mut two_headers = vanilla(&vanilla_authorization());
        two_headers.headers_mut().append(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&vanilla_authorization()).expect("valid header value"),
        );
        assert!(rejection(&two_headers, &aws_params()).contains("multiple Authorization"));

        let no_equal = format!("{}, Garbage", vanilla_authorization());
        assert!(rejection(&vanilla(&no_equal), &aws_params()).contains("missing '='"));
    }

    #[test]
    fn missing_or_invalid_timestamp_is_rejected() {
        let request = http::Request::builder()
            .uri("/")
            .header("Host", AWS_HOST)
            .header("Authorization", vanilla_authorization())
            .body(Bytes::new())
            .expect("valid test request");
        assert!(rejection(&request, &aws_params()).contains("missing X-Amz-Date or Date"));

        let request = http::Request::builder()
            .uri("/")
            .header("Host", AWS_HOST)
            .header("X-Amz-Date", "2015-08-30T12:36:00Z")
            .header("Authorization", vanilla_authorization())
            .body(Bytes::new())
            .expect("valid test request");
        assert!(rejection(&request, &aws_params()).contains("invalid request timestamp"));
    }

    #[test]
    fn uri_path_normalization() {
        for (path, canonical) in [
            ("", "/"),
            ("/a//b/", "/a/b/"),
            ("/a/./b/../c", "/a/c"),
            ("/a/b/../", "/a/"),
            ("/a/%2E/b/%2e%2e/c", "/a/c"),
            ("/%e1%88%b4", "/%E1%88%B4"),
            ("/%41%7e", "/A~"),
            ("/a%2Fb", "/a%2Fb"),
            ("/a+b", "/a%20b"),
            ("/a:b@c", "/a%3Ab%40c"),
        ] {
            assert_eq!(canonical_uri_path(path), Ok(canonical.to_owned()), "{path}");
        }
        for (path, reason) in [
            ("/..", "above the root"),
            ("/a/../..", "above the root"),
            // `%2E%2E` decodes to a `..` segment and must not escape the root either.
            ("/%2E%2E/x", "above the root"),
            ("/%zz", "invalid percent-encoding"),
            ("/%4", "incomplete percent-encoding"),
            ("*", "not absolute"),
        ] {
            let error = canonical_uri_path(path).expect_err("path must be rejected");
            assert!(error.contains(reason), "{path}: {error}");
        }
    }

    /// Sorted by encoded name then value, as the AWS spec requires.
    #[test]
    fn query_string_normalization() {
        assert_eq!(
            canonical_query_string("b=2&a=2&a=1&&c&a%2d=%7e+"),
            Ok("a=1&a=2&a-=~%20&b=2&c=".to_owned())
        );
        let error = canonical_query_string("a=%G1").expect_err("invalid escape");
        assert!(error.contains("invalid percent-encoding"), "{error}");
    }
}
