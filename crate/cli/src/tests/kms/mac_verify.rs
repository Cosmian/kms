use cosmian_kms_client::reexport::cosmian_kms_client_utils::create_utils::SymmetricAlgorithm;
use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::{
        mac::{CHashingAlgorithm, MacAction, MacVerifyAction},
        symmetric::keys::create_key::CreateKeyAction,
    },
    error::result::KmsCliResult,
};

#[tokio::test]
pub(super) async fn test_mac_verify() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    let mac_key_id = CreateKeyAction {
        algorithm: SymmetricAlgorithm::Sha3,
        number_of_bits: Some(256),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let data_hex = "01".repeat(64);

    // Compute MAC first
    let compute = MacAction {
        mac_key_id: mac_key_id.to_string(),
        hashing_algorithm: CHashingAlgorithm::SHA3_256,
        data: Some(data_hex.clone()),
        correlation_value: None,
        init_indicator: false,
        final_indicator: false,
    };
    compute.run(ctx.get_owner_client()).await?;

    // Compute MAC again to get the value (through direct client)
    let mac_resp = ctx
        .get_owner_client()
        .mac(
            cosmian_kms_client::kmip_2_1::kmip_operations::MAC {
                unique_identifier: Some(
                    cosmian_kms_client::kmip_2_1::kmip_types::UniqueIdentifier::TextString(
                        mac_key_id.to_string(),
                    ),
                ),
                cryptographic_parameters: Some(
                    cosmian_kms_client::kmip_2_1::kmip_types::CryptographicParameters {
                        hashing_algorithm: Some(
                            cosmian_kms_client::cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm::SHA3256,
                        ),
                        ..Default::default()
                    },
                ),
                data: Some(hex::decode(&data_hex)?),
                correlation_value: None,
                init_indicator: Some(false),
                final_indicator: Some(false),
            },
        )
        .await?;
    let mac_hex = hex::encode(mac_resp.mac_data.unwrap_or_default());

    // Verify
    MacVerifyAction {
        mac_key_id: mac_key_id.to_string(),
        hashing_algorithm: CHashingAlgorithm::SHA3_256,
        data: data_hex,
        mac_hex,
    }
    .run(ctx.get_owner_client())
    .await?;

    Ok(())
}
