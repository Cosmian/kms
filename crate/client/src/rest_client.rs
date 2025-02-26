use crate::{
    config::RestClientConfig,
    error::{
        result::{ClientResult, FindexRestClientResultHelper},
        ClientError,
    },
};
use cosmian_http_client::HttpClient;
use reqwest::{Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use tracing::trace;
use uuid::Uuid;

// Response for success
#[derive(Deserialize, Serialize, Debug)] // Debug is required by ok_json()
pub struct SuccessResponse {
    pub success: String,
    pub index_id: Uuid,
}

impl Display for SuccessResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.success)
    }
}

#[derive(Clone)]
pub struct RestClient {
    pub http_client: HttpClient,
}

impl RestClient {
    /// Initialize a Findex REST client.
    ///
    /// Parameters `server_url` and `accept_invalid_certs` from the command line
    /// will override the ones from the configuration file.
    /// # Errors
    /// Return an error if the configuration file is not found or if the
    /// configuration is invalid or if the client cannot be instantiated.
    pub fn new(config: &RestClientConfig) -> Result<Self, ClientError> {
        // Instantiate a Findex server REST client with the given configuration
        let client = HttpClient::instantiate(&config.http_config).with_context(|| {
            format!(
                "Unable to instantiate a Findex REST client to server at {}",
                config.http_config.server_url
            )
        })?;

        Ok(Self {
            http_client: client,
        })
    }

    // #[instrument(ret(Display), err, skip(self))]
    /// # Errors
    /// Return an error if the request fails.
    pub async fn version(&self) -> ClientResult<String> {
        let endpoint = "/version";
        let server_url = format!("{}{endpoint}", self.http_client.server_url);
        let response = self.http_client.client.get(server_url).send().await?;
        if response.status().is_success() {
            return Ok(response.json::<String>().await?);
        }

        // process error
        let p = handle_error(endpoint, response).await?;
        Err(ClientError::RequestFailed(p))
    }
}

/// Handle the status code of the response.
pub(crate) async fn handle_status_code(
    response: Response,
    endpoint: &str,
) -> ClientResult<SuccessResponse> {
    if response.status().is_success() {
        Ok(response.json::<SuccessResponse>().await?)
    } else {
        let p = handle_error(endpoint, response).await?;
        Err(ClientError::RequestFailed(p))
    }
}

/// Some errors are returned by the Middleware without going through our own
/// error manager. In that case, we make the error clearer here for the client.
/// # Errors
/// Return an error if the response cannot be read.
/// Return an error if the response is not a success.
pub async fn handle_error(endpoint: &str, response: Response) -> Result<String, ClientError> {
    trace!("Error response received on {endpoint}: Response: {response:?}");
    let status = response.status();
    let text = response.text().await?;

    Ok(format!(
        "{}: {}",
        endpoint,
        if text.is_empty() {
            match status {
                StatusCode::NOT_FOUND => "Findex server endpoint does not exist".to_owned(),
                StatusCode::UNAUTHORIZED => "Bad authorization token".to_owned(),
                _ => format!("{status} {text}"),
            }
        } else {
            text
        }
    ))
}
