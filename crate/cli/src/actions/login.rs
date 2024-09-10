use std::{
    collections::HashMap,
    path::PathBuf,
    sync::mpsc::{self, Sender},
    thread,
};

use actix_web::{
    get,
    web::{self, Data},
    App, HttpResponse, HttpServer,
};
use clap::Parser;
use cosmian_kms_client::ClientConf;
use oauth2::{
    basic::BasicClient,
    http::{
        self,
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap, HeaderValue, StatusCode,
    },
    AuthUrl, ClientId, ClientSecret, CsrfToken, HttpRequest, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenUrl,
};
use serde::Deserialize;
use url::Url;

use crate::{
    cli_bail,
    error::{result::CliResult, CliError},
};

/// Login to the Identity Provider of the KMS server using the `OAuth2` authorization code flow.
///
/// This command will open a browser window and ask you to login to the Identity Provider.
/// Once you have logged in, the access token will be saved in the ckms configuration file.
///
/// The configuration file must contain an `oauth2_conf` object with the following fields:
/// - `client_id`: The client ID of your application. This is provided by the Identity Provider.
/// - `client_secret`: The client secret of your application. This is provided by the Identity Provider.
/// - `authorize_url`: The authorization URL of the provider. For example, for Google it is `https://accounts.google.com/o/oauth2/v2/auth`.
/// - `token_url`: The token URL of the provider. For example, for Google it is `https://oauth2.googleapis.com/token`.
/// - `scopes`: The scopes to request. For example, for Google it is `["openid", "email"]`.
///
/// The callback url must be authorized on the Identity Provider with value `http://localhost:17899/token`.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct LoginAction;

impl LoginAction {
    /// This function processes the login action.
    /// It loads the client configuration from the specified path, retrieves the `OAuth2` configuration,
    /// initializes the login state, prompts the user to browse to the authorization URL,
    /// finalizes the login process by receiving the authorization code and exchanging it for an access token,
    /// updates the configuration with the access token, and saves the configuration to the specified path.
    ///
    /// # Arguments
    ///
    /// * `conf_path` - The path to the client configuration file.
    ///
    /// # Errors
    ///
    /// This function can return a `CliError` in the following cases:
    ///
    /// * The `login` command requires an Identity Provider (`IdP`) that must be configured in the `oauth2_conf` object in the client configuration file.
    /// * The client configuration file cannot be loaded.
    /// * The `OAuth2` configuration is missing or invalid in the client configuration file.
    /// * The authorization URL cannot be parsed.
    /// * The authorization code is not received or does not match the CSRF token.
    /// * The access token cannot be requested from the Identity Provider.
    /// * The token exchange request fails.
    /// * The token exchange response cannot be parsed.
    /// * The client configuration cannot be updated or saved.
    #[allow(clippy::print_stdout)]
    pub async fn process(&self, conf_path: &PathBuf) -> CliResult<()> {
        let mut conf = ClientConf::load(conf_path)?;
        let oauth2_conf = conf.oauth2_conf.as_ref().ok_or_else(|| {
            CliError::Default(format!(
                "The `login` command (only used for JWT authentication) requires an Identity \
                 Provider (IdP) that MUST be configured in the oauth2_conf object in {conf_path:?}"
            ))
        })?;
        let login_config = Oauth2LoginConfig {
            client_id: oauth2_conf.client_id.clone(),
            client_secret: oauth2_conf.client_secret.clone(),
            authorize_url: oauth2_conf.authorize_url.clone(),
            token_url: oauth2_conf.token_url.clone(),
            scopes: oauth2_conf.scopes.clone(),
        };

        let state = LoginState::try_from(login_config)?;
        println!("Browse to: {}", state.auth_url);
        let access_token = state.finalize().await?;

        // update the configuration and save it
        conf.kms_access_token = Some(access_token);
        conf.save(conf_path)?;

        println!(
            "\nSuccess! The access token was saved in the KMS configuration file: {conf_path:?}"
        );

        Ok(())
    }
}

pub struct Oauth2LoginConfig {
    /// The client ID of your application.
    pub client_id: String,
    /// The client secret of your application.
    pub client_secret: String,
    /// The authorization URL of the provider.
    /// For example, for Google it is `https://accounts.google.com/o/oauth2/v2/auth`.
    pub authorize_url: String,
    /// The token URL of the provider.
    /// For example, for Google it is `https://oauth2.googleapis.com/token`.
    pub token_url: String,
    /// The scopes to request.
    /// For example, for Google it is `["openid", "email"]`.
    pub scopes: Vec<String>,
}

/// This struct holds the state of the login process.
/// It is used to generate the authorization URL and to store the PKCE verifier and the CSRF token.
///
/// The user should browse to the authorization URL and follow the instructions to authenticate.
/// The Url can be recovered by accessing to field `auth_url`.
///
/// The CSRF token is used to verify that the authorization code received on the redirect URL
/// matches the one generated by the client.
/// The PKCE verifier is used to verify that the authorization code received on the redirect URL
/// matches the one generated by the client.
/// See [RFC 7636](https://tools.ietf.org/html/rfc7636) for more details.
/// See [PKCE](https://oauth.net/2/pkce/) for more details.
/// See [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery) for more details.
/// See [OAuth2](https://oauth.net/2/) for more details.
/// See [OAuth2 RFC](https://tools.ietf.org/html/rfc6749) for more details.
pub struct LoginState {
    login_config: Oauth2LoginConfig,
    redirect_url: Url,
    pub(crate) auth_url: Url,
    pkce_verifier: PkceCodeVerifier,
    csrf_token: CsrfToken,
}

/// This function initializes the login process.
/// It returns a `LoginState` that holds the state of the login process.
///
/// The process should be completed by instructing the user to browse to the authorization URL and follow the instructions to authenticate
/// and immediately after calling `finalize()` with the returned `LoginState`.
///
/// The Url can be recovered by accessing `auth_url` on the returned `LoginState` struct.
impl TryFrom<Oauth2LoginConfig> for LoginState {
    type Error = CliError;

    fn try_from(login_config: Oauth2LoginConfig) -> Result<Self, Self::Error> {
        let mut redirect_url = Url::parse("http://localhost:17899/authorization")?;
        // if the port is specified in the environment variable, use it
        if let Ok(port_s) = std::env::var("KMS_CLI_OAUTH2_REDIRECT_URL_PORT") {
            let port = port_s.parse::<u16>().map_err(|e| {
                CliError::Default(format!("Invalid KMS_CLI_OAUTH2_REDIRECT_URL_PORT: {e:?}"))
            })?;
            redirect_url.set_port(Some(port)).map_err(|e| {
                CliError::Default(format!("Invalid KMS_CLI_OAUTH2_REDIRECT_URL_PORT: {e:?}"))
            })?;
        }

        // Create an OAuth2 client by specifying the client ID, client secret,
        // authorization URL and token URL.
        let client = BasicClient::new(
            ClientId::new(login_config.client_id.clone()),
            Some(ClientSecret::new(login_config.client_secret.clone())),
            AuthUrl::new(login_config.authorize_url.clone())?,
            Some(TokenUrl::new(login_config.token_url.clone())?),
        )
        // Set the URL the user will be redirected to after the authorization process.
        .set_redirect_uri(RedirectUrl::new(redirect_url.to_string())?);

        // Generate a PKCE challenge.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let scopes = login_config
            .scopes
            .iter()
            .map(|s| Scope::new(s.clone()))
            .collect::<Vec<_>>();

        // Generate the full authorization URL.
        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            // Set the desired scopes.
            .add_scopes(scopes)
            // Set the PKCE code challenge.
            .set_pkce_challenge(pkce_challenge)
            .url();

        // This is the URL you should redirect the user to,
        // in order to trigger the authorization process.
        Ok(Self {
            login_config,
            redirect_url,
            auth_url,
            pkce_verifier,
            csrf_token,
        })
    }
}

impl LoginState {
    /// This function finalizes the login process.
    /// It returns the access token.
    ///
    /// This function should be called immediately after the user has been instructed to browse to the authorization URL.
    /// It starts a server on localhost:17899 and waits for the authorization code to be received
    /// from the browser window. Once the code is received, the server is closed and the code is returned.
    ///
    /// # Errors
    ///
    /// This function can return a `CliError` in the following cases:
    ///
    /// * The authorization code, state, or other parameters are not received from the redirect URL.
    /// * The received state does not match the CSRF token.
    /// * The authorization code is not received on authentication.
    /// * The code received on authentication does not match the CSRF token.
    /// * The access token cannot be requested from the Identity Provider.
    /// * The token exchange request fails.
    /// * The token exchange response cannot be parsed.
    pub async fn finalize(&self) -> CliResult<String> {
        // recover the authorization code, state and other parameters from the redirect URL
        let auth_parameters = Self::receive_authorization_parameters()?;

        // Once the user has been redirected to the redirect URL, you'll have access to the
        // authorization code. For security reasons, your code should verify that the `state`
        // parameter returned by the server matches `csrf_state`.
        let received_state = auth_parameters
            .get("state")
            .ok_or_else(|| CliError::Default("state not received on authentication".to_owned()))?;
        if received_state != self.csrf_token.secret() {
            return Err(CliError::Default(
                "state received on authentication does not match".to_owned(),
            ))
        }

        // extract the authorization code
        let authorization_code = auth_parameters
            .get("code")
            .ok_or_else(|| CliError::Default("code not received on authentication".to_owned()))?;

        // Now you can trade it for an access token.

        // TODO: unfortunately, the following does not work because Google return the JWT token in the `id_token` field, not the access_token field
        // let token_result = login_state
        //     .client
        //     .exchange_code(AuthorizationCode::new(authorization_code.to_string()))
        //     // Set the PKCE code verifier.
        //     .set_pkce_verifier(login_state.pkce_verifier)
        //     .request_async(async_http_client)
        //     .await
        //     .map_err(|e| CliError::Default(format!("token exchange failed: {:?}", e)))?;

        let token_result = request_token(
            &self.login_config,
            &self.redirect_url,
            &self.pkce_verifier,
            authorization_code,
        )
        .await?;

        Ok(match token_result.id_token {
            // this is where Google returns the JWT token
            Some(id_token) => id_token,
            None => token_result.access_token,
        })
    }

    /// This function starts the server on `localhost:17899` and waits for the authorization code to be received
    /// from the browser window. Once the code is received, the server is closed and the authorization code is returned.
    fn receive_authorization_parameters() -> CliResult<HashMap<String, String>> {
        let (auth_params_tx, auth_params_rx) = mpsc::channel::<HashMap<String, String>>();
        // Spawn the server into a runtime
        let tokio_handle = tokio::runtime::Handle::current();
        let _task = thread::spawn(move || {
            tokio_handle.block_on({
                // server.await
                #[get("/authorization")]
                async fn authorization_handler(
                    auth_params: web::Query<HashMap<String, String>>,
                    auth_params_tx: Data<Sender<HashMap<String, String>>>,
                ) -> HttpResponse {
                    auth_params_tx
                        .into_inner()
                        .send(auth_params.into_inner())
                        .unwrap();
                    HttpResponse::Ok().body("You can now close this window.")
                }

                HttpServer::new(move || {
                    App::new()
                        .app_data(Data::new(auth_params_tx.clone()))
                        .service(authorization_handler)
                })
                .bind(("127.0.0.1", 17899))?
                .run()
            })
        });
        auth_params_rx
            .recv()
            .map_err(|e| CliError::Default(format!("authorization code not received: {e:?}")))
    }
}

#[derive(Deserialize, Debug)]
pub struct OAuthResponse {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip)]
    pub expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
}

/// This function requests the access token from the Identity Provider.
///
/// This function was rewritten because Google returns the JWT token in the `id_token` field,
/// not in the `access_token` field.
///
/// For Google see: <https://developers.google.com/identity/openid-connect/openid-connect#obtainuserinfo>
///
/// # Arguments
///
/// * `login_config` - The `Oauth2LoginConfig` containing the client configuration.
/// * `redirect_url` - The redirect URL used in the `OAuth2` flow.
/// * `pkce_verifier` - The PKCE code verifier used in the `OAuth2` flow.
/// * `authorization_code` - The authorization code received from the Identity Provider.
///
/// # Errors
///
/// This function can return a `CliError` in the following cases:
///
/// * The token exchange request fails.
/// * The token exchange response cannot be parsed.
pub async fn request_token(
    login_config: &Oauth2LoginConfig,
    redirect_url: &Url,
    pkce_verifier: &PkceCodeVerifier,
    authorization_code: &str,
) -> CliResult<OAuthResponse> {
    let params = vec![
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect_url.as_str()),
        ("client_id", login_config.client_id.as_str()),
        ("code", authorization_code),
        ("client_secret", login_config.client_secret.as_str()),
        ("code_verifier", pkce_verifier.secret()),
    ];

    let mut headers = HeaderMap::new();
    headers.append(ACCEPT, HeaderValue::from_static("application/json"));
    headers.append(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );

    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish()
        .into_bytes();

    let request = HttpRequest {
        url: Url::parse(&login_config.token_url)?,
        method: http::method::Method::POST,
        headers,
        body,
    };

    let response = oauth2::reqwest::async_http_client(request)
        .await
        .map_err(|e| CliError::Default(format!("failed issuing token exchange request: {e:?}")))?;

    if response.status_code != StatusCode::OK {
        cli_bail!(
            "failed token exchange: {}",
            String::from_utf8_lossy(response.body.as_slice())
        )
    }

    let response_body = response.body.as_slice();

    serde_json::from_slice(response_body)
        .map_err(|e| CliError::Default(format!("failed parsing token exchange response: {e:?}")))
}
