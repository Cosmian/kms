//! AWS Systems Manager Parameter Store backend.

use chrono::Utc;
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};

use super::{
    AwsSsmBackendConfig, KResult, KmsError, SecretBackend,
    common::{http_json, parse_uri, require_non_empty, resolve_async},
};

pub(super) struct AwsSsmBackend {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

impl AwsSsmBackend {
    pub(super) fn new(cfg: &AwsSsmBackendConfig) -> Self {
        Self {
            access_key_id: cfg.aws_access_key_id.clone(),
            secret_access_key: cfg.aws_secret_access_key.clone(),
            session_token: cfg.aws_session_token.clone(),
        }
    }

    /// Build a SigV4-signed request and call the SSM `GetParameter` API.
    async fn call_ssm(&self, region: &str, param: &str, uri: &str) -> KResult<serde_json::Value> {
        let now = Utc::now();
        let dt = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();
        let host = format!("ssm.{region}.amazonaws.com");
        let body = serde_json::json!({"Name": param, "WithDecryption": true}).to_string();
        let payload_hash = sha256_hex(body.as_bytes())?;

        let (canon_hdrs, signed_hdrs) =
            Self::canonical_headers(&host, &dt, self.session_token.as_deref());
        let canon_req = format!("POST\n/\n\n{canon_hdrs}\n{signed_hdrs}\n{payload_hash}");
        let scope = format!("{date}/{region}/ssm/aws4_request");
        let sts = format!(
            "AWS4-HMAC-SHA256\n{dt}\n{scope}\n{}",
            sha256_hex(canon_req.as_bytes())?
        );
        let key = signing_key(&self.secret_access_key, &date, region, "ssm")?;
        let sig = hex::encode(&hmac_sha256(&key, sts.as_bytes())?);
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_hdrs}, Signature={sig}",
            self.access_key_id
        );

        let mut req = reqwest::Client::new()
            .post(format!("https://{host}/"))
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("X-Amz-Date", &dt)
            .header("X-Amz-Target", "AmazonSSM.GetParameter")
            .header("Authorization", &auth);
        if let Some(t) = &self.session_token {
            req = req.header("X-Amz-Security-Token", t);
        }

        http_json(req.body(body), uri, "AWS SSM").await
    }

    fn canonical_headers(host: &str, dt: &str, token: Option<&str>) -> (String, String) {
        token.map_or_else(
            || (
                format!("content-type:application/x-amz-json-1.1\nhost:{host}\nx-amz-date:{dt}\nx-amz-target:AmazonSSM.GetParameter\n"),
                "content-type;host;x-amz-date;x-amz-target".to_owned(),
            ),
            |t| (
                format!("content-type:application/x-amz-json-1.1\nhost:{host}\nx-amz-date:{dt}\nx-amz-security-token:{t}\nx-amz-target:AmazonSSM.GetParameter\n"),
                "content-type;host;x-amz-date;x-amz-security-token;x-amz-target".to_owned(),
            ),
        )
    }
}

// ─── SigV4 helpers (using OpenSSL) ───────────────────────────────────────────

fn sha256_hex(data: &[u8]) -> KResult<String> {
    let digest = openssl::hash::hash(MessageDigest::sha256(), data)
        .map_err(|e| KmsError::ServerError(format!("SHA-256 error: {e}")))?;
    Ok(hex::encode(digest))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> KResult<Vec<u8>> {
    let pkey =
        PKey::hmac(key).map_err(|e| KmsError::ServerError(format!("HMAC key error: {e}")))?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)
        .map_err(|e| KmsError::ServerError(format!("HMAC signer init error: {e}")))?;
    signer
        .update(data)
        .map_err(|e| KmsError::ServerError(format!("HMAC update error: {e}")))?;
    signer
        .sign_to_vec()
        .map_err(|e| KmsError::ServerError(format!("HMAC finalize error: {e}")))
}

fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> KResult<Vec<u8>> {
    let k = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes())?;
    let k = hmac_sha256(&k, region.as_bytes())?;
    let k = hmac_sha256(&k, service.as_bytes())?;
    hmac_sha256(&k, b"aws4_request")
}

// ─── SecretBackend impl ─────────────────────────────────────────────────────

impl SecretBackend for AwsSsmBackend {
    fn resolve(&self, uri: &str) -> KResult<String> {
        require_non_empty(&self.access_key_id, "AWS_ACCESS_KEY_ID", "aws-ssm")?;
        require_non_empty(&self.secret_access_key, "AWS_SECRET_ACCESS_KEY", "aws-ssm")?;

        let (region, param_with_slash) = parse_uri(uri, "aws-ssm", "secret://<region>/<param>")?;
        let param_name = format!("/{param_with_slash}");
        let region = region.to_owned();
        let uri_owned = uri.to_owned();
        // Clone self fields for the 'static async block
        let backend = Self {
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
            session_token: self.session_token.clone(),
        };

        resolve_async(async move {
            let json = backend.call_ssm(&region, &param_name, &uri_owned).await?;

            json.get("Parameter")
                .and_then(|p| p.get("Value"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    KmsError::ServerError(format!(
                        "AWS SSM missing Parameter.Value for {uri_owned}"
                    ))
                })
                .map(str::to_owned)
        })
    }
}
