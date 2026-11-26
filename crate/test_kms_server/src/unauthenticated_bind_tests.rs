//! F-003 (#1486): a server without any authentication method refuses a non-loopback bind.

use crate::{TestClientOptions, start_test_server_with_patch, test_config_path};

/// `auth/none.toml` configures no authentication. With the development opt-in cleared and a
/// non-loopback bind, starting must fail closed instead of serving every caller as
/// `default_username`.
#[tokio::test]
async fn no_auth_server_refuses_non_loopback_bind() {
    crate::init_test_logging();
    let result = start_test_server_with_patch(
        &test_config_path("auth/none.toml"),
        |config| {
            "0.0.0.0".clone_into(&mut config.http.hostname);
            config.http.insecure_allow_unauthenticated = false;
        },
        TestClientOptions::default(),
    )
    .await;
    match result {
        Ok(context) => {
            context.stop_server().await.unwrap();
            panic!("a server without authentication bound to 0.0.0.0 must refuse to start");
        }
        Err(error) => assert!(
            error.to_string().contains("refusing to start"),
            "unexpected startup error: {error}"
        ),
    }
}
