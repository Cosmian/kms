use std::sync::Arc;

use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::EMPTY_TAGS,
    kmip_operations::{Sign, SignResponse},
    requests::create_rsa_key_pair_request,
};
use zeroize::Zeroizing;

use crate::{
    config::{
        ClapConfig, GoogleCseConfig, MainDBConfig, ServerParams, SocketServerConfig, TlsConfig,
    },
    core::KMS,
    result::KResult,
};

const TEST_DATA: &[u8] = b"Hello, world! This is a test message for signing.";

#[tokio::test]
async fn test_rsa_sign() -> KResult<()> {
    cosmian_logger::log_init(option_env!("RUST_LOG"));

    // Use a simpler configuration without TLS
    let clap_config = ClapConfig {
        socket_server: SocketServerConfig {
            socket_server_start: false,
            ..Default::default()
        },
        tls: TlsConfig::default(),
        db: MainDBConfig {
            sqlite_path: "/tmp/test_sign_rsa.db".into(),
            ..Default::default()
        },
        google_cse_config: GoogleCseConfig::default(),
        ..Default::default()
    };

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "test_user_rsa_sign";

    // Create RSA key pair
    let request = create_rsa_key_pair_request(
        None,       // private_key_id
        EMPTY_TAGS, // tags
        2048,       // cryptographic_length
        false,      // sensitive
        None,       // wrapping_key_id
    )?;
    let response = kms.create_key_pair(request, owner, None, None).await?;
    let private_key_id = response.private_key_unique_identifier;

    // Test signing with data
    let sign_request = Sign {
        unique_identifier: Some(private_key_id.clone()),
        cryptographic_parameters: None,
        data: Some(Zeroizing::new(TEST_DATA.to_vec())),
        digested_data: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
    };

    let sign_response: SignResponse = kms.sign(sign_request, owner, None).await?;

    // Verify we got a signature back
    assert_eq!(sign_response.unique_identifier, private_key_id);
    assert!(sign_response.signature_data.is_some());
    let signature = sign_response.signature_data.unwrap();

    // RSA 2048 PSS signature should be 256 bytes
    assert_eq!(signature.len(), 256);

    Ok(())
}
