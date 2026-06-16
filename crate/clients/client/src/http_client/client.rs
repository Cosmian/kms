use bytes::Bytes;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_openssl::client::legacy::HttpsConnector;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use serde::{Deserialize, Deserializer, Serialize};
use tracing::{info, warn};

use super::{
    Oauth2LoginConfig, ProxyParams,
    error::{HttpClientError, result::HttpClientResult},
    proxy::SmartConnector,
    tls::build_ssl_connector,
};

/// Configuration for the HTTP client
///
/// # Examples
///
/// ## Basic HTTP client
/// ```rust
/// use cosmian_kms_client::http_client::HttpClientConfig;
///
/// let config = HttpClientConfig::default();
/// ```
///
/// ## HTTP client with custom cipher suites
/// ```rust
/// use cosmian_kms_client::http_client::HttpClientConfig;
///
/// let mut config = HttpClientConfig::default();
/// config.cipher_suites = Some("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256".to_string());
/// ```
///
/// ## Supported cipher suites
/// - TLS 1.3: `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`,
///   `TLS_CHACHA20_POLY1305_SHA256`
/// - TLS 1.2 ECDHE-ECDSA: `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`,
///   `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`,
///   `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
/// - TLS 1.2 ECDHE-RSA: `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`,
///   `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`,
///   `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
#[derive(Serialize, Eq, PartialEq, Debug, Clone)]
pub struct HttpClientConfig {
    // accept_invalid_certs is useful if the cli needs to connect to an HTTPS server
    // running an invalid or insecure TLS certificate
    #[serde(default)]
    #[serde(skip_serializing_if = "not")]
    pub accept_invalid_certs: bool,
    pub server_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_pkcs12_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_pkcs12_password: Option<String>,
    /// Optional path to a client certificate in PEM format.
    /// If provided along with `tls_client_pem_key_path`, it will be used for
    /// client authentication instead of PKCS#12.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_pem_cert_path: Option<String>,
    /// Optional path to a client private key in PEM format.
    /// Used together with `tls_client_pem_cert_path` for client authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_pem_key_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth2_conf: Option<Oauth2LoginConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_params: Option<ProxyParams>,
    /// Colon-separated list of cipher suites to use for TLS connections.
    /// Note: Custom cipher suites are not supported with native-tls.
    /// Server-side cipher suite configuration is available through server
    /// configuration.
    ///
    /// Example: "`TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256`"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suites: Option<String>,
    /// Custom HTTP headers to add to every request.
    /// Each entry must be in `"Header-Name: value"` format (same as curl's `-H`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_headers: Option<Vec<String>>,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            accept_invalid_certs: false,
            server_url: "http://127.0.0.1:9998".to_owned(),
            verified_cert: None,
            access_token: None,
            database_secret: None,
            tls_client_pkcs12_path: None,
            tls_client_pkcs12_password: None,
            tls_client_pem_cert_path: None,
            tls_client_pem_key_path: None,
            oauth2_conf: None,
            proxy_params: None,
            cipher_suites: None,
            custom_headers: None,
        }
    }
}

/// used for serialization
#[allow(clippy::trivially_copy_pass_by_ref)]
const fn not(b: &bool) -> bool {
    !*b
}

/// Intermediate struct used to deserialise `HttpClientConfig` from TOML/JSON.
///
/// Keeping both the canonical `tls_client_*` names and the legacy `ssl_client_*`
/// names as distinct fields lets us detect which key was actually present in the
/// config file and emit a deprecation warning before merging the values.
#[derive(Deserialize)]
struct HttpClientConfigDeserHelper {
    #[serde(default)]
    accept_invalid_certs: bool,
    server_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
    // Canonical (new) names
    tls_client_pkcs12_path: Option<String>,
    tls_client_pkcs12_password: Option<String>,
    tls_client_pem_cert_path: Option<String>,
    tls_client_pem_key_path: Option<String>,
    // Legacy (deprecated) names — accepted but trigger a warning
    ssl_client_pkcs12_path: Option<String>,
    ssl_client_pkcs12_password: Option<String>,
    ssl_client_pem_cert_path: Option<String>,
    ssl_client_pem_key_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    database_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oauth2_conf: Option<Oauth2LoginConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proxy_params: Option<ProxyParams>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cipher_suites: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    custom_headers: Option<Vec<String>>,
}

impl<'de> Deserialize<'de> for HttpClientConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = HttpClientConfigDeserHelper::deserialize(deserializer)?;

        // Emit deprecation warnings for legacy ssl_ fields and merge into tls_ fields.
        macro_rules! merge_deprecated {
            ($new:expr, $old:expr, $old_name:literal, $new_name:literal) => {{
                if $old.is_some() {
                    warn!(
                        "ckms config: `{}` is deprecated — rename it to `{}` in your \
                         ckms.toml to silence this warning.",
                        $old_name, $new_name
                    );
                }
                // New name takes precedence if both are set.
                $new.or($old)
            }};
        }

        Ok(Self {
            accept_invalid_certs: raw.accept_invalid_certs,
            server_url: raw.server_url,
            verified_cert: raw.verified_cert,
            access_token: raw.access_token,
            tls_client_pkcs12_path: merge_deprecated!(
                raw.tls_client_pkcs12_path,
                raw.ssl_client_pkcs12_path,
                "ssl_client_pkcs12_path",
                "tls_client_pkcs12_path"
            ),
            tls_client_pkcs12_password: merge_deprecated!(
                raw.tls_client_pkcs12_password,
                raw.ssl_client_pkcs12_password,
                "ssl_client_pkcs12_password",
                "tls_client_pkcs12_password"
            ),
            tls_client_pem_cert_path: merge_deprecated!(
                raw.tls_client_pem_cert_path,
                raw.ssl_client_pem_cert_path,
                "ssl_client_pem_cert_path",
                "tls_client_pem_cert_path"
            ),
            tls_client_pem_key_path: merge_deprecated!(
                raw.tls_client_pem_key_path,
                raw.ssl_client_pem_key_path,
                "ssl_client_pem_key_path",
                "tls_client_pem_key_path"
            ),
            database_secret: raw.database_secret,
            oauth2_conf: raw.oauth2_conf,
            proxy_params: raw.proxy_params,
            cipher_suites: raw.cipher_suites,
            custom_headers: raw.custom_headers,
        })
    }
}

/// An HTTP response from the server.
pub struct HttpResponse {
    /// HTTP status code.
    pub status: http::StatusCode,
    /// Response body as raw bytes.
    body: Bytes,
}

impl HttpResponse {
    /// Deserialize the response body as JSON.
    ///
    /// # Errors
    /// Returns an error if the body is not valid JSON for type `T`.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> HttpClientResult<T> {
        serde_json::from_slice(&self.body).map_err(|e| {
            HttpClientError::Default(format!("Failed to deserialize response body as JSON: {e}"))
        })
    }

    /// Return the response body as a UTF-8 string.
    ///
    /// # Errors
    /// Returns an error if the body is not valid UTF-8.
    pub fn text(&self) -> HttpClientResult<String> {
        String::from_utf8(self.body.to_vec())
            .map_err(|e| HttpClientError::Default(format!("Response body is not UTF-8: {e}")))
    }

    /// Return the raw response body bytes.
    #[must_use]
    pub const fn bytes(&self) -> &Bytes {
        &self.body
    }
}

/// The inner hyper client type used by [`HttpClient`].
type InnerClient = Client<HttpsConnector<SmartConnector>, Full<Bytes>>;

/// A struct implementing some of the 50+ operations a KMIP client should
/// implement: <https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip>
#[derive(Clone)]
pub struct HttpClient {
    pub server_url: String,
    client: InnerClient,
    default_headers: HeaderMap,
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClient")
            .field("server_url", &self.server_url)
            .finish_non_exhaustive()
    }
}

impl HttpClient {
    /// Instantiate a new HTTP(S) Client backed by OpenSSL for TLS.
    ///
    /// Supports PQC algorithms (ML-DSA, ML-KEM, SLH-DSA) via OpenSSL 3.6.2.
    ///
    /// # Errors
    /// Will return an error if the client cannot be instantiated
    pub fn instantiate(http_conf: &HttpClientConfig) -> Result<Self, HttpClientError> {
        // Validate client authentication configuration: either PKCS#12 (with password)
        // or PEM (cert + key), but not both or partially provided
        let pem_cert_set = http_conf.tls_client_pem_cert_path.is_some();
        let pem_key_set = http_conf.tls_client_pem_key_path.is_some();
        let pkcs12_set = http_conf.tls_client_pkcs12_path.is_some();
        let pkcs12_pwd_set = http_conf.tls_client_pkcs12_password.is_some();

        if (pem_cert_set || pem_key_set) && (pkcs12_set || pkcs12_pwd_set) {
            return Err(HttpClientError::Default(
                "Invalid configuration: cannot use both PKCS#12 and PEM client authentication"
                    .to_owned(),
            ));
        }

        if pem_cert_set ^ pem_key_set {
            return Err(HttpClientError::Default(
                "Invalid configuration: both PEM certificate and key paths must be provided"
                    .to_owned(),
            ));
        }

        if pkcs12_set && !pkcs12_pwd_set {
            return Err(HttpClientError::Default(
                "Invalid configuration: PKCS#12 password must be provided with PKCS#12 path"
                    .to_owned(),
            ));
        }

        // Ensure the server URL does not end with a slash
        let server_url = http_conf
            .server_url
            .strip_suffix('/')
            .map_or_else(|| http_conf.server_url.clone(), str::to_owned);
        info!("Using server URL: {}", server_url);

        // Build default headers
        let mut headers = HeaderMap::new();
        if let Some(bearer_token) = http_conf.access_token.clone() {
            headers.insert(
                "Authorization",
                HeaderValue::from_str(format!("Bearer {bearer_token}").as_str())?,
            );
        }
        if let Some(database_secret) = http_conf.database_secret.clone() {
            headers.insert("DatabaseSecret", HeaderValue::from_str(&database_secret)?);
        }

        // Apply any user-supplied custom headers
        if let Some(ref custom_headers) = http_conf.custom_headers {
            for header_str in custom_headers {
                let (name, value) = header_str.split_once(':').ok_or_else(|| {
                    HttpClientError::Default(format!(
                        "Invalid custom header '{header_str}': expected 'Name: Value' format"
                    ))
                })?;
                let header_name = HeaderName::from_bytes(name.trim().as_bytes()).map_err(|e| {
                    HttpClientError::Default(format!("Invalid header name '{name}': {e}"))
                })?;
                let header_value = HeaderValue::from_str(value.trim()).map_err(|e| {
                    HttpClientError::Default(format!("Invalid header value for '{name}': {e}"))
                })?;
                headers.insert(header_name, header_value);
            }
        }

        // Build OpenSSL connector
        let ssl_builder = build_ssl_connector(http_conf)?;

        // Build the smart connector (handles proxy or direct connections)
        let connector =
            http_conf
                .proxy_params
                .as_ref()
                .map_or_else(SmartConnector::direct, |proxy_params| {
                    info!("Using proxy: {:?}", proxy_params);
                    SmartConnector::with_proxy(proxy_params.clone())
                });

        // Wrap with HTTPS (OpenSSL TLS)
        let https_connector =
            HttpsConnector::with_connector(connector, ssl_builder).map_err(|e| {
                HttpClientError::Default(format!("Failed to build HTTPS connector: {e}"))
            })?;

        // Build hyper client with connection pooling
        let client = Client::builder(TokioExecutor::new()).build(https_connector);

        Ok(Self {
            server_url,
            client,
            default_headers: headers,
        })
    }

    /// Send an HTTP GET request.
    ///
    /// # Errors
    /// Returns an error if the request fails.
    pub async fn get(&self, url: &str) -> HttpClientResult<HttpResponse> {
        let mut builder = http::Request::builder().method("GET").uri(url);
        for (name, value) in &self.default_headers {
            builder = builder.header(name, value);
        }
        let request = builder
            .body(Full::new(Bytes::new()))
            .map_err(|e| HttpClientError::Default(format!("Failed to build GET request: {e}")))?;

        self.send(request).await
    }

    /// Send an HTTP GET request with query parameters serialized from `query`.
    ///
    /// # Errors
    /// Returns an error if the request fails.
    pub async fn get_with_query<Q: Serialize>(
        &self,
        url: &str,
        query: &Q,
    ) -> HttpClientResult<HttpResponse> {
        let query_string = serde_urlencoded::to_string(query).map_err(|e| {
            HttpClientError::Default(format!("Failed to serialize query params: {e}"))
        })?;
        let full_url = if query_string.is_empty() {
            url.to_owned()
        } else {
            format!("{url}?{query_string}")
        };
        self.get(&full_url).await
    }

    /// Send an HTTP POST request with a JSON body.
    ///
    /// # Errors
    /// Returns an error if the request fails.
    pub async fn post_json<B: Serialize>(
        &self,
        url: &str,
        body: &B,
    ) -> HttpClientResult<HttpResponse> {
        let json_bytes = serde_json::to_vec(body).map_err(|e| {
            HttpClientError::Default(format!("Failed to serialize request body: {e}"))
        })?;

        let mut builder = http::Request::builder()
            .method("POST")
            .uri(url)
            .header("Content-Type", "application/json");
        for (name, value) in &self.default_headers {
            builder = builder.header(name, value);
        }
        let request = builder
            .body(Full::new(Bytes::from(json_bytes)))
            .map_err(|e| HttpClientError::Default(format!("Failed to build POST request: {e}")))?;

        self.send(request).await
    }

    /// Send an HTTP POST request with raw bytes and a specified content type.
    ///
    /// # Errors
    /// Returns an error if the request fails.
    pub async fn post_bytes(
        &self,
        url: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> HttpClientResult<HttpResponse> {
        let mut builder = http::Request::builder()
            .method("POST")
            .uri(url)
            .header("Content-Type", content_type);
        for (name, value) in &self.default_headers {
            builder = builder.header(name, value);
        }
        let request = builder
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| HttpClientError::Default(format!("Failed to build POST request: {e}")))?;

        self.send(request).await
    }

    /// Send an HTTP POST request without a body.
    ///
    /// # Errors
    /// Returns an error if the request fails.
    pub async fn post_empty(&self, url: &str) -> HttpClientResult<HttpResponse> {
        let mut builder = http::Request::builder().method("POST").uri(url);
        for (name, value) in &self.default_headers {
            builder = builder.header(name, value);
        }
        let request = builder
            .body(Full::new(Bytes::new()))
            .map_err(|e| HttpClientError::Default(format!("Failed to build POST request: {e}")))?;

        self.send(request).await
    }

    /// Send an HTTP DELETE request with a JSON body.
    ///
    /// # Errors
    /// Returns an error if the request fails.
    pub async fn delete_json<B: Serialize>(
        &self,
        url: &str,
        body: &B,
    ) -> HttpClientResult<HttpResponse> {
        let json_bytes = serde_json::to_vec(body).map_err(|e| {
            HttpClientError::Default(format!("Failed to serialize request body: {e}"))
        })?;

        let mut builder = http::Request::builder()
            .method("DELETE")
            .uri(url)
            .header("Content-Type", "application/json");
        for (name, value) in &self.default_headers {
            builder = builder.header(name, value);
        }
        let request = builder
            .body(Full::new(Bytes::from(json_bytes)))
            .map_err(|e| {
                HttpClientError::Default(format!("Failed to build DELETE request: {e}"))
            })?;

        self.send(request).await
    }

    /// Send an HTTP POST with form-urlencoded body (for `OAuth2` token exchange).
    ///
    /// # Errors
    /// Returns an error if the request fails.
    pub async fn post_form(
        &self,
        url: &str,
        form_body: &str,
        extra_headers: &HeaderMap,
    ) -> HttpClientResult<HttpResponse> {
        let mut builder = http::Request::builder()
            .method("POST")
            .uri(url)
            .header("Content-Type", "application/x-www-form-urlencoded");
        for (name, value) in &self.default_headers {
            builder = builder.header(name, value);
        }
        for (name, value) in extra_headers {
            builder = builder.header(name, value);
        }
        let request = builder
            .body(Full::new(Bytes::from(form_body.to_owned())))
            .map_err(|e| HttpClientError::Default(format!("Failed to build POST request: {e}")))?;

        self.send(request).await
    }

    /// Send a prepared HTTP request and collect the response.
    async fn send(&self, request: http::Request<Full<Bytes>>) -> HttpClientResult<HttpResponse> {
        let response: http::Response<Incoming> = self
            .client
            .request(request)
            .await
            .map_err(|e| HttpClientError::Default(format!("HTTP request failed: {e}")))?;

        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|e| HttpClientError::Default(format!("Failed to read response body: {e}")))?
            .to_bytes();

        Ok(HttpResponse { status, body })
    }
}
