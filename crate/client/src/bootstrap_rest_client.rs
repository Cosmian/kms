use std::{
    io::{BufReader, Read},
    path::PathBuf,
    time::Duration,
};

// re-export the kmip module as kmip
use cosmian_kms_utils::access::SuccessResponse;
use http::{HeaderMap, HeaderValue, StatusCode};
use reqwest::{
    multipart::{Form, Part},
    Body, Client, ClientBuilder, Identity, Response,
};
use serde::{Deserialize, Serialize};
use tokio_util::codec::{BytesCodec, FramedRead};

use crate::error::RestClientError;

/// A struct implementing some of the 50+ operations a KMIP client should implement:
/// <https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip>
#[derive(Clone)]
pub struct BootstrapRestClient {
    server_url: String,
    client: Client,
}

impl BootstrapRestClient {
    /// This operation requests the server to revoke an access on an object to a user
    /// The user could be unknown from the database.
    /// The object uid must be known from the database.
    /// If the user already has no access, nothing is done. No error is returned.
    pub async fn upload_pkcs12(
        &self,
        pkcs12_file: &PathBuf,
    ) -> Result<SuccessResponse, RestClientError> {
        self.upload("/pkcs12", pkcs12_file).await
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

        // Build the client
        Ok(Self {
            client: builder
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