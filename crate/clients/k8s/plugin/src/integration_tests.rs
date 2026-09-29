use std::{collections::HashMap, time::Duration};

use cosmian_kms_client::{
    KmsClient, KmsClientConfig,
    http_client::HttpClientConfig,
    kmip_2_1::{kmip_types::CryptographicAlgorithm, requests::symmetric_key_create_request},
};
use test_kms_server::start_default_test_kms_server;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use crate::{
    kmsv2::{
        DecryptRequest, EncryptRequest, StatusRequest,
        key_management_service_client::KeyManagementServiceClient,
        key_management_service_server::KeyManagementServiceServer,
    },
    service::KmsPluginService,
};

/// Start a `KmsPluginService` gRPC server on a temp Unix socket and return
/// a connected `KeyManagementServiceClient`.
#[allow(clippy::expect_used, dead_code)]
async fn start_plugin_on_tmp_socket(
    kms_url: &str,
    wrapping_key_uid: String,
) -> (
    KeyManagementServiceClient<Channel>,
    String,
    tokio::task::JoinHandle<()>,
) {
    let socket_path = format!(
        "/tmp/kubernetes-kms-plugin-test-{}.sock",
        uuid::Uuid::new_v4()
    );

    let http_config = HttpClientConfig {
        server_url: kms_url.to_owned(),
        ..HttpClientConfig::default()
    };
    let kms_client = KmsClient::new_with_config(KmsClientConfig {
        http_config,
        ..KmsClientConfig::default()
    })
    .expect("KmsClient should build");

    let service = KmsPluginService::new(kms_client, wrapping_key_uid);
    let listener = UnixListener::bind(&socket_path).expect("bind unix socket");
    let incoming = UnixListenerStream::new(listener);

    let socket_path_clone = socket_path.clone();
    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(KeyManagementServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .expect("gRPC server should not error");
        drop(std::fs::remove_file(&socket_path_clone));
    });

    // Wait for the server to accept connections (avoid flakiness from fixed sleeps).
    for _ in 0..50 {
        match tokio::net::UnixStream::connect(&socket_path).await {
            Ok(stream) => {
                drop(stream);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }

    let socket_path_for_connect = socket_path.clone();
    // tonic 0.12 uses hyper 1.x — tokio::net::UnixStream must be wrapped
    // with TokioIo to implement the hyper::rt::io::Read/Write traits.
    let channel = Endpoint::try_from("http://[::]:50051")
        .expect("endpoint")
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = socket_path_for_connect.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .expect("connect to unix socket");

    let client = KeyManagementServiceClient::new(channel);
    (client, socket_path, handle)
}

/// Creates an AES-256-GCM KEK via the Cosmian KMS, then exercises the full
/// gRPC Encrypt → Decrypt cycle through the plugin service.
///
/// This test validates:
/// - `Status` returns `version="v2"`, `healthz="ok"`, correct `key_id`
/// - `Encrypt` wraps a 32-byte DEK, returns non-empty ciphertext and `key_id`
/// - `Decrypt` unwraps to the original DEK bytes
/// - A wrong `key_id` on `Decrypt` returns an error
#[allow(clippy::expect_used)]
#[tokio::test]
async fn test_grpc_encrypt_decrypt_roundtrip() {
    test_kms_server::init_test_logging();

    // Start an in-process KMS server (SQLite, no auth).
    let ctx = start_default_test_kms_server().await;
    let kms_url = ctx.owner_client_config.http_config.server_url.clone();

    // Create the KEK on the KMS using the test context client.
    let kms_client = ctx.get_owner_client();
    let create_request = symmetric_key_create_request(
        "cosmian",
        None,
        256,
        CryptographicAlgorithm::AES,
        Vec::<String>::new(),
        false,
        None,
    )
    .expect("create request");
    let create_resp = kms_client.create(create_request).await.expect("create KEK");
    let kek_uid = create_resp.unique_identifier.to_string();

    // Start the gRPC plugin server pointing at the same KMS.
    let (mut plugin_client, socket_path, server_handle) =
        start_plugin_on_tmp_socket(&kms_url, kek_uid.clone()).await;

    // ── Status ────────────────────────────────────────────────────────────
    let status = plugin_client
        .status(StatusRequest {})
        .await
        .expect("status call")
        .into_inner();
    assert_eq!(status.version, "v2", "version must be v2");
    assert_eq!(status.healthz, "ok", "healthz must be ok");
    assert_eq!(status.key_id, kek_uid, "key_id must match KEK UID");

    // ── Encrypt (wrap DEK) ────────────────────────────────────────────────
    let dek: Vec<u8> = b"k8s-plugin-test-dek-0123456789AB".to_vec();
    let enc_resp = plugin_client
        .encrypt(EncryptRequest {
            plaintext: dek.clone(),
            uid: "test-uid-enc-001".to_owned(),
        })
        .await
        .expect("encrypt call")
        .into_inner();

    assert!(
        !enc_resp.ciphertext.is_empty(),
        "ciphertext must not be empty"
    );
    assert_eq!(
        enc_resp.key_id, kek_uid,
        "encrypt key_id must match KEK UID"
    );

    // ── Decrypt (unwrap DEK) ──────────────────────────────────────────────
    let dec_resp = plugin_client
        .decrypt(DecryptRequest {
            ciphertext: enc_resp.ciphertext,
            uid: "test-uid-dec-001".to_owned(),
            key_id: enc_resp.key_id,
            annotations: enc_resp.annotations,
        })
        .await
        .expect("decrypt call")
        .into_inner();

    assert_eq!(dec_resp.plaintext, dek, "decrypted DEK must match original");

    // ── Key-id mismatch is rejected ───────────────────────────────────────
    let bad_dec = plugin_client
        .decrypt(DecryptRequest {
            ciphertext: b"garbage".to_vec(),
            uid: "test-uid-bad".to_owned(),
            key_id: "wrong-key-id".to_owned(),
            annotations: HashMap::new(),
        })
        .await;
    assert!(bad_dec.is_err(), "wrong key_id must be rejected");

    // Cleanup
    server_handle.abort();
    drop(std::fs::remove_file(&socket_path));
}
