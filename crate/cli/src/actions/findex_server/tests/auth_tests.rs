use cosmian_logger::log_init;
use test_findex_server::{
    get_redis_url, start_test_server_with_options, AuthenticationOptions, DBConfig, DatabaseType,
};
use tracing::{info, trace};

use crate::error::result::CosmianResult;

// let us not make other test cases fail
const PORT: u16 = 6667;

#[tokio::test]
pub(crate) async fn test_all_authentications() -> CosmianResult<()> {
    log_init(None);
    let url = get_redis_url("REDIS_URL");
    trace!("TESTS: using redis on {url}");
    // plaintext no auth
    info!("Testing server with no auth");
    let ctx = start_test_server_with_options(
        DBConfig {
            database_type: DatabaseType::Redis,
            clear_database: false,
            database_url: url.clone(),
        },
        PORT,
        AuthenticationOptions {
            use_jwt_token: false,
            use_https: false,
            use_client_cert: false,
        },
    )
    .await?;
    ctx.stop_server().await?;

    let default_db_config = DBConfig {
        database_type: DatabaseType::Redis,
        clear_database: false,
        database_url: url,
    };

    // plaintext JWT token auth
    info!("Testing server with JWT token auth");
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        PORT,
        AuthenticationOptions {
            use_jwt_token: true,
            use_https: false,
            use_client_cert: false,
        },
    )
    .await?;
    ctx.stop_server().await?;

    // tls token auth
    info!("Testing server with TLS token auth");
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        PORT,
        AuthenticationOptions {
            use_jwt_token: true,
            use_https: true,
            use_client_cert: false,
        },
    )
    .await?;
    ctx.stop_server().await?;

    // On recent versions of macOS, the root Certificate for the client is searched
    // on the keychains and not found, since it is a local self-signed
    // certificate. This is likely a bug in reqwest
    #[cfg(not(target_os = "macos"))]
    {
        // tls client cert auth
        info!("Testing server with TLS client cert auth");
        let ctx = start_test_server_with_options(
            default_db_config.clone(),
            PORT,
            AuthenticationOptions {
                use_jwt_token: false,
                use_https: true,
                use_client_cert: true,
            },
        )
        .await?;
        ctx.stop_server().await?;

        // Good JWT token auth but still cert auth used at first
        info!(
            "Testing server with bad API token and good JWT token auth but still cert auth used \
             at first"
        );
        let ctx = start_test_server_with_options(
            default_db_config,
            PORT,
            AuthenticationOptions {
                use_jwt_token: true,
                use_https: true,
                use_client_cert: true,
            },
        )
        .await?;
        ctx.stop_server().await?;
    }

    Ok(())
}
