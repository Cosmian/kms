use std::{collections::HashMap, future::Future, pin::Pin, process::Command};

use assert_cmd::prelude::*;

use super::utils::recover_cmd_logs;
use crate::{
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{access::SUB_COMMAND, utils::start_test_server_with_options, PROG_NAME},
};

fn run_cli_command(owner_cli_conf_path: &str) {
    let mut cmd = Command::cargo_bin(PROG_NAME).expect(" cargo bin failed");
    cmd.env(KMS_CLI_CONF_ENV, owner_cli_conf_path);
    cmd.env("RUST_LOG", "cosmian_kms_cli=debug");
    cmd.arg(SUB_COMMAND).args(vec!["owned"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().success();
}

#[tokio::test]
pub async fn test_all_authentications() -> Result<(), CliError> {
    // let us not make other test cases fail
    const PORT: u16 = 9999;
    // plaintext no auth
    let ctx = start_test_server_with_options(PORT, false, false, false, false, false).await;
    run_cli_command(&ctx.owner_cli_conf_path);
    ctx.stop_server().await;

    // plaintext token auth
    let ctx = start_test_server_with_options(PORT, true, false, false, false, false).await;
    run_cli_command(&ctx.owner_cli_conf_path);
    ctx.stop_server().await;

    // tls token auth
    let ctx = start_test_server_with_options(PORT, true, true, false, false, false).await;
    run_cli_command(&ctx.owner_cli_conf_path);
    ctx.stop_server().await;

    // tls client cert auth
    let ctx = start_test_server_with_options(PORT, false, true, true, false, false).await;
    run_cli_command(&ctx.owner_cli_conf_path);
    ctx.stop_server().await;

    Ok(())
}

use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use url::Url;

#[tokio::test]
pub async fn authorization_code_grant_test() -> Result<(), CliError> {
    const CLIENT_ID: &str =
        "996739510374-au9fdbgp72dacrsag267ckg32jf3d3e2.apps.googleusercontent.com";
    const CLIENT_SECRET: &str = "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";
    const AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
    const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

    // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
    // token URL.
    let client = BasicClient::new(
        ClientId::new(CLIENT_ID.to_string()),
        Some(ClientSecret::new(CLIENT_SECRET.to_string())),
        AuthUrl::new(AUTHORIZE_URL.to_string())?,
        Some(TokenUrl::new(TOKEN_URL.to_string())?),
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(RedirectUrl::new(
        "http://localhost:17899/token".to_string(),
    )?);

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let scopes = vec![
        Scope::new("openid".to_string()),
        Scope::new("profile".to_string()),
    ];

    // Generate the full authorization URL.
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        // Set the desired scopes.
        .add_scopes(scopes)
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    // // This is the URL you should redirect the user to, in order to trigger the authorization
    // // process.
    println!("csrf token: {:?}", csrf_token);
    println!("Browse to: {}", auth_url);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (tx, rx) = std::sync::mpsc::channel::<HashMap<String, String>>();

    let server = wait_for_token(shutdown_rx, tx);

    // Spawn the server into a runtime
    tokio::task::spawn(server);

    let tokio_handle = tokio::runtime::Handle::current();
    let thread_handle = std::thread::spawn(move || {
        tokio_handle
            .block_on(wait_for_token(tx))
            .map_err(|e| CliError::ServerError(e.to_string()))
    });
    let server_handle = rx
        .recv_timeout(Duration::from_secs(25))
        .expect("Can't get test bootstrap server handle after 25 seconds");

    // shutdown server
    shutdown_tx.send(())?;

    // // Once the user has been redirected to the redirect URL, you'll have access to the
    // // authorization code. For security reasons, your code should verify that the `state`
    // // parameter returned by the server matches `csrf_state`.

    // // Now you can trade it for an access token.
    // let token_result = client
    //     .exchange_code(AuthorizationCode::new(
    //         "some authorization code".to_string(),
    //     ))
    //     // Set the PKCE code verifier.
    //     .set_pkce_verifier(pkce_verifier)
    //     .request_async(async_http_client)
    //     .await?;

    Ok(())
}

use tokio::sync::oneshot;
use warp::Filter;

async fn wait_for_token(
    shutdown_rx: oneshot::Receiver<()>,
    tx: std::sync::mpsc::Sender<HashMap<String, String>>,
) -> Box<dyn Future<Output = ()> + Send> {
    // Create a warp server.
    let route = warp::path("token")
        .and(warp::query::<HashMap<String, String>>())
        .map(move |params| {
            // Do something with the query parameters.
            println!("params: {:?}", params);
            tx.send(params).unwrap();
            "ok"
        });

    let (_addr, server) =
        warp::serve(route).bind_with_graceful_shutdown(([127, 0, 0, 1], 17899), async {
            shutdown_rx.await.ok();
        });

    Box::new(server)
}
