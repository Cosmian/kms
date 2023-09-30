use std::{
    io::{BufReader, Read},
    path::PathBuf,
    time::Duration,
};

// re-export the kmip module as kmip
use cosmian_kms_utils::access::SuccessResponse;
use http::{HeaderMap, HeaderValue, StatusCode};
use openssl::x509::X509;
use ratls::{
    verify::{get_server_certificate, verify_ratls},
    TeeMeasurement,
};
use reqwest::{
    multipart::{Form, Part},
    Body, Certificate, Client, ClientBuilder, Identity, Response,
};
use serde::{Deserialize, Serialize};
use tokio_util::codec::{BytesCodec, FramedRead};
use url::Url;

use crate::error::RestClientError;

/// A struct implementing some of the 50+ operations a KMIP client should implement:
/// <https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip>
#[derive(Clone)]
pub struct BootstrapRestClient {
    server_url: String,
    client: Client,
}

impl BootstrapRestClient {
    /// Upload a PKCS12 file containing the KMS server's SSL certificate and private key.
    /// The KMS server will be started in HTTPS mode.
    ///
    /// Call the `pkcs12_password()` method to supply the PKCS12 password
    /// if it is a non-empty string,
    pub async fn upload_pkcs12(
        &self,
        pkcs12_file: &PathBuf,
    ) -> Result<SuccessResponse, RestClientError> {
        self.upload("/pkcs12", pkcs12_file).await
    }

    pub async fn set_pkcs12_password(
        &self,
        pkcs12_password: &str,
    ) -> Result<SuccessResponse, RestClientError> {
        #[derive(Serialize)]
        pub struct PasswordConfig {
            pub password: String,
        }
        self.post(
            "/pkcs12-password",
            Some(&PasswordConfig {
                password: pkcs12_password.to_string(),
            }),
        )
        .await
    }

    pub async fn set_redis_findex_config(
        &self,
        database_url: &str,
        master_password: &str,
        findex_label: &str,
    ) -> Result<SuccessResponse, RestClientError> {
        #[derive(Serialize)]
        pub struct RedisFindexConfig {
            pub url: String,
            pub master_password: String,
            pub findex_label: String,
        }
        self.post(
            "/redis-findex",
            Some(&RedisFindexConfig {
                url: database_url.to_string(),
                master_password: master_password.to_string(),
                findex_label: findex_label.to_string(),
            }),
        )
        .await
    }

    pub async fn set_postgresql_config(
        &self,
        database_url: &str,
    ) -> Result<SuccessResponse, RestClientError> {
        #[derive(Serialize)]
        pub struct UrlConfig {
            pub url: String,
        }
        self.post(
            "/postgresql",
            Some(&UrlConfig {
                url: database_url.to_string(),
            }),
        )
        .await
    }

    pub async fn set_mysql_config(
        &self,
        database_url: &str,
    ) -> Result<SuccessResponse, RestClientError> {
        #[derive(Serialize)]
        pub struct UrlConfig {
            pub url: String,
        }
        self.post(
            "/mysql",
            Some(&UrlConfig {
                url: database_url.to_string(),
            }),
        )
        .await
    }

    pub async fn set_sqlite_config(
        &self,
        path: &PathBuf,
    ) -> Result<SuccessResponse, RestClientError> {
        #[derive(Serialize)]
        pub struct PathConfig {
            pub path: String,
        }
        self.post(
            "/sqlite",
            Some(&PathConfig {
                path: path
                    .to_str()
                    .ok_or_else(|| {
                        RestClientError::Default(format!("Invalid sqlite path: {path:?}"))
                    })?
                    .to_string(),
            }),
        )
        .await
    }

    pub async fn set_sqlite_enc_config(
        &self,
        path: &PathBuf,
    ) -> Result<SuccessResponse, RestClientError> {
        #[derive(Serialize)]
        pub struct PathConfig {
            pub path: String,
        }
        self.post(
            "/sqlite-enc",
            Some(&PathConfig {
                path: path
                    .to_str()
                    .ok_or_else(|| {
                        RestClientError::Default(format!("Invalid sqlite-enc path: {path:?}"))
                    })?
                    .to_string(),
            }),
        )
        .await
    }

    pub async fn start_kms_server(
        &self,
        clear_database: bool,
    ) -> Result<SuccessResponse, RestClientError> {
        #[derive(Serialize)]
        pub struct StartKmsServer {
            pub clear_database: bool,
        }
        self.post("/start", Some(&StartKmsServer { clear_database }))
            .await
    }
}

impl BootstrapRestClient {
    /// Instantiate a new KMIP REST Client
    #[allow(dead_code)]
    pub fn instantiate(
        bootstrap_server_url: &str,
        bearer_token: Option<&str>,
        ssl_client_pkcs12_path: Option<&str>,
        ssl_client_pkcs12_password: Option<&str>,
        measurement: Option<TeeMeasurement>,
    ) -> Result<Self, RestClientError> {
        let server_url = match bootstrap_server_url.strip_suffix('/') {
            Some(s) => s.to_string(),
            None => bootstrap_server_url.to_string(),
        };

        let mut headers = HeaderMap::new();
        if let Some(bearer_token) = bearer_token {
            headers.insert(
                "Authorization",
                HeaderValue::from_str(format!("Bearer {bearer_token}").as_str())?,
            );
        }
        headers.insert("Connection", HeaderValue::from_static("keep-alive"));

        // Create a client builder hat accepts invalid certs
        let builder = ClientBuilder::new().danger_accept_invalid_certs(true);

        // If a PKCS12 file is provided, use it to build the client
        let builder = match ssl_client_pkcs12_path {
            Some(ssl_client_pkcs12) => {
                let mut pkcs12 = BufReader::new(std::fs::File::open(ssl_client_pkcs12)?);
                let mut pkcs12_bytes = vec![];
                pkcs12.read_to_end(&mut pkcs12_bytes)?;
                let pkcs12 = Identity::from_pkcs12_der(
                    &pkcs12_bytes,
                    ssl_client_pkcs12_password.unwrap_or(""),
                )?;
                builder.identity(pkcs12)
            }
            None => builder,
        };

        // Get and verify the ratls certificate in order to use it as the only valid root CA
        let bootstrap_server_url = Url::parse(bootstrap_server_url)?;

        let ratls_cert = get_server_certificate(
            bootstrap_server_url
                .host_str()
                .ok_or(RestClientError::Default(
                    "Missing 'hostname' in bootstrap server url".to_string(),
                ))?,
            u32::from(bootstrap_server_url.port().unwrap_or(443)),
        )
        .map_err(|e| RestClientError::RatlsError(format!("Can't get RATLS certificate: {e}")))?;

        let ratls_cert = X509::from_der(&ratls_cert)
            .map_err(|e| {
                RestClientError::RatlsError(format!("Can't convert certificate to DER: {e}"))
            })?
            .to_pem()
            .map_err(|e| {
                RestClientError::RatlsError(format!("Can't convert certificate to PEM: {e}"))
            })?;

        verify_ratls(&ratls_cert, measurement)
            .map_err(|e| RestClientError::RatlsError(e.to_string()))?;

        let ratls_cert = Certificate::from_pem(&ratls_cert)?;

        // Build the client
        Ok(Self {
            client: builder
                .tls_built_in_root_certs(false) // Disallow all root certs from the system
                .add_root_certificate(ratls_cert) // Allow our ratls cert
                .connect_timeout(Duration::from_secs(5))
                .tcp_keepalive(Duration::from_secs(30))
                .default_headers(headers)
                .build()?,
            server_url,
        })
    }

    pub async fn post<O, R>(&self, endpoint: &str, data: Option<&O>) -> Result<R, RestClientError>
    where
        O: Serialize,
        R: serde::de::DeserializeOwned + Sized + 'static,
    {
        let server_url = format!("{}{endpoint}", self.server_url);
        let response = match data {
            Some(d) => self.client.post(server_url).json(d).send().await?,
            None => self.client.post(server_url).send().await?,
        };

        let status_code = response.status();
        if status_code.is_success() {
            return Ok(response.json::<R>().await?)
        }

        // process error
        let p = handle_error(response).await?;
        Err(RestClientError::RequestFailed(p))
    }

    pub async fn upload<R>(&self, endpoint: &str, file: &PathBuf) -> Result<R, RestClientError>
    where
        R: serde::de::DeserializeOwned + Sized + 'static,
    {
        let server_url = format!("{}{endpoint}", self.server_url);

        // open the file async
        let file = tokio::fs::File::open(file).await?;

        // create a body wrapping the async file stream
        let stream = FramedRead::new(file, BytesCodec::new());
        let file_body = Body::wrap_stream(stream);

        //make a form part of the file
        let file_part = Part::stream(file_body)
            .file_name("bootstrap.p12")
            .mime_str("application/octet-stream")?;

        //create the multipart form
        let form = Form::new().part("file", file_part);

        //send request
        let response = self.client.post(server_url).multipart(form).send().await?;

        // check the status code response
        let status_code = response.status();
        if status_code.is_success() {
            return Ok(response.json::<R>().await?)
        }

        // process error
        let p = handle_error(response).await?;
        Err(RestClientError::RequestFailed(p))
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ErrorPayload {
    pub error: String,
    pub messages: Option<Vec<String>>,
}

/// Some errors are returned by the Middleware without going through our own error manager.
/// In that case, we make the error clearer here for the client.
async fn handle_error(response: Response) -> Result<String, RestClientError> {
    let status = response.status();
    let text = response.text().await?;

    if !text.is_empty() {
        Ok(text)
    } else {
        Ok(match status {
            StatusCode::NOT_FOUND => "Bootstrap server endpoint does not exist".to_string(),
            StatusCode::UNAUTHORIZED => "Bad authorization token".to_string(),
            _ => format!("{status} {text}"),
        })
    }
}
