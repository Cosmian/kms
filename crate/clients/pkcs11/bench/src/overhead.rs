//! Differential Ed25519 signing tiers used to attribute the gap between the
//! published pre-serialized HTTP benchmark and a real PKCS#11 `C_Sign`.

use std::{
    hint::black_box,
    sync::atomic::{AtomicUsize, Ordering},
};

use ckms::reexport::cosmian_kms_cli_actions::reexport::{
    cosmian_kmip::{
        kmip_0::{
            kmip_messages::{
                RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
                ResponseMessage, ResponseMessageBatchItemVersioned,
            },
            kmip_types::{ProtocolVersion, ResultStatusEnumeration},
        },
        kmip_2_1::{
            kmip_messages::RequestMessageBatchItem,
            kmip_operations::{Operation, Sign, SignResponse},
            kmip_types::{OperationEnumeration, UniqueIdentifier},
        },
        ttlv::{KmipFlavor, TTLV, from_ttlv, to_ttlv},
    },
    cosmian_kms_client::{KmsClient, KmsClientError},
};
use criterion::Criterion;
use pkcs11_sys::{CKK_EC_EDWARDS, CKM_EDDSA, CKO_PRIVATE_KEY};
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

use crate::{
    error::{BenchError, BenchResult},
    loader::{Pkcs11Session, SIGN_PROFILE_PHASE_NAMES, SignPhaseSnapshot},
    report::{OverheadMetadata, OverheadPhase},
};

const ED25519_SIGNATURE_LEN: usize = 64;
const PROFILE_SAMPLES: usize = 2_000;
const GROUP: &str = "pkcs11-overhead_eddsa-ed25519";

fn sign_request(private_key_id: &UniqueIdentifier, message: &[u8]) -> Sign {
    Sign {
        unique_identifier: Some(private_key_id.clone()),
        data: Some(Zeroizing::new(message.to_vec())),
        ..Default::default()
    }
}

fn wire_request(sign: Sign) -> RequestMessage {
    RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem::new(Operation::Sign(sign)),
        )],
    }
}

fn map_setup_error(context: &str, error: impl std::fmt::Display) -> BenchError {
    BenchError::Setup(format!("{context}: {error}"))
}

fn validate_binary_sign_response(bytes: &[u8]) -> BenchResult<()> {
    let ttlv = TTLV::from_bytes(bytes, KmipFlavor::Kmip2)
        .map_err(|error| map_setup_error("parse binary Sign response TTLV", error))?;
    let response: ResponseMessage = from_ttlv(ttlv)
        .map_err(|error| map_setup_error("deserialize binary Sign response", error))?;
    if response.batch_item.len() != 1 {
        return Err(BenchError::Setup(format!(
            "binary Sign response has {} batch items, expected one",
            response.batch_item.len()
        )));
    }
    let item =
        response.batch_item.into_iter().next().ok_or_else(|| {
            BenchError::Setup("binary Sign response has no batch item".to_owned())
        })?;
    let ResponseMessageBatchItemVersioned::V21(item) = item else {
        return Err(BenchError::Setup(
            "binary Sign response is not KMIP 2.1".to_owned(),
        ));
    };
    if item.result_status != ResultStatusEnumeration::Success
        || item.operation != Some(OperationEnumeration::Sign)
    {
        return Err(BenchError::Setup(format!(
            "binary Sign response failed or had wrong operation: status={}, operation={:?}",
            item.result_status, item.operation
        )));
    }
    let Some(Operation::SignResponse(response)) = item.response_payload else {
        return Err(BenchError::Setup(
            "binary Sign response has no SignResponse payload".to_owned(),
        ));
    };
    if response.signature_data.as_ref().map(Vec::len) != Some(ED25519_SIGNATURE_LEN) {
        return Err(BenchError::Setup(
            "binary Sign response did not contain a 64-byte signature".to_owned(),
        ));
    }
    Ok(())
}

fn histogram_quantile(snapshot: &SignPhaseSnapshot, quantile: f64) -> u64 {
    if snapshot.count == 0 {
        return 0;
    }
    let target = (snapshot.count as f64 * quantile).ceil() as u64;
    let mut cumulative = 0_u64;
    for (index, count) in snapshot.buckets.iter().enumerate() {
        cumulative += count;
        if cumulative >= target {
            return if index < 32 {
                u64::try_from(index).unwrap_or(31)
            } else {
                let relative = index - 32;
                let exponent = 5 + relative / 2;
                let sub_bucket = relative % 2;
                if exponent >= u64::BITS as usize {
                    u64::MAX
                } else {
                    let base = 1_u64 << exponent;
                    let step = base / 2;
                    base.saturating_add(
                        step.saturating_mul(u64::try_from(sub_bucket + 1).unwrap_or(2)),
                    )
                    .saturating_sub(1)
                }
            };
        }
    }
    snapshot.max_ns
}

fn profile_phases(snapshot: &crate::loader::SignProfileSnapshot) -> Vec<OverheadPhase> {
    SIGN_PROFILE_PHASE_NAMES
        .iter()
        .zip(&snapshot.phases)
        .filter(|(_, phase)| phase.count > 0)
        .map(|(name, phase)| OverheadPhase {
            name,
            count: phase.count,
            mean_ns: phase.total_ns as f64 / phase.count as f64,
            p50_ns: histogram_quantile(phase, 0.50),
            p95_ns: histogram_quantile(phase, 0.95),
            p99_ns: histogram_quantile(phase, 0.99),
            max_ns: phase.max_ns,
        })
        .collect()
}

/// Adds comparable Ed25519 signing tiers to `criterion`.
///
/// All tiers use the same KMS client, key, 32-byte payload, endpoint, runtime, and
/// Criterion configuration. This makes each incremental delta meaningful:
///
/// - the published-style tier uses a pre-serialized full `RequestMessage` and only
///   collects the HTTP response body;
/// - the bare-sign raw tier uses the exact request shape sent by `KmsClient::sign`;
/// - the typed tier includes TTLV/JSON serialization and response parsing;
/// - the PKCS#11 tiers add the C ABI, module/provider dispatch, and sync-to-async
///   bridge; the standard two-call tier guards against regressing to the historical
///   behavior where `C_Sign(NULL)` caused a second remote Sign.
pub(crate) fn add_overhead_benchmarks(
    criterion: &mut Criterion,
    runtime: &Runtime,
    client: &KmsClient,
    private_key_id: &UniqueIdentifier,
    session: &Pkcs11Session<'_>,
    payload_size: usize,
    vary_payload: bool,
) -> BenchResult<OverheadMetadata> {
    if payload_size == 0 {
        return Err(BenchError::Setup(
            "--overhead-payload-size must be at least 1".to_owned(),
        ));
    }
    let message = vec![0x42_u8; payload_size];
    let varying_messages: Vec<Vec<u8>> = (0_u64..1024)
        .map(|counter| {
            let mut value = message.clone();
            for (target, source) in value.iter_mut().zip(counter.to_le_bytes()) {
                *target = source;
            }
            value
        })
        .collect();
    let request = sign_request(private_key_id, &message);
    let bare_ttlv =
        to_ttlv(&request).map_err(|e| map_setup_error("serialize bare Sign TTLV", e))?;
    let bare_body = serde_json::to_vec(&bare_ttlv)
        .map_err(|e| map_setup_error("serialize bare Sign JSON", e))?;

    let full_ttlv = to_ttlv(&wire_request(request.clone()))
        .map_err(|e| map_setup_error("serialize RequestMessage TTLV", e))?;
    let full_body = serde_json::to_vec(&full_ttlv)
        .map_err(|e| map_setup_error("serialize RequestMessage JSON", e))?;
    let full_binary_body = full_ttlv
        .to_bytes(KmipFlavor::Kmip2)
        .map_err(|e| map_setup_error("serialize RequestMessage binary TTLV", e))?;

    let endpoint = format!("{}/kmip/2_1", client.client.server_url);
    let binary_endpoint = format!("{}/kmip", client.client.server_url);
    let published_probe = runtime
        .block_on(
            client
                .client
                .post_bytes(&endpoint, full_body.clone(), "application/json"),
        )
        .map_err(|e| map_setup_error("probe published-equivalent Sign request", e))?;
    if !published_probe.status.is_success() {
        return Err(BenchError::Setup(format!(
            "published-equivalent Sign probe returned HTTP {}",
            published_probe.status
        )));
    }
    let binary_probe = runtime
        .block_on(client.client.post_bytes(
            &binary_endpoint,
            full_binary_body.clone(),
            "application/octet-stream",
        ))
        .map_err(|e| map_setup_error("probe binary-TTLV Sign request", e))?;
    if !binary_probe.status.is_success() {
        return Err(BenchError::Setup(format!(
            "binary-TTLV Sign probe returned HTTP {}",
            binary_probe.status
        )));
    }
    let binary_response_body = binary_probe.bytes().to_vec();
    validate_binary_sign_response(&binary_response_body)?;
    let parse_response = runtime
        .block_on(
            client
                .client
                .post_bytes(&endpoint, bare_body.clone(), "application/json"),
        )
        .map_err(|e| map_setup_error("capture Sign response", e))?;
    if !parse_response.status.is_success() {
        return Err(BenchError::Setup(format!(
            "capture Sign response returned HTTP {}",
            parse_response.status
        )));
    }
    let response_body = parse_response.bytes().to_vec();

    let private_key = session.find_first_by_class_and_key_type(CKO_PRIVATE_KEY, CKK_EC_EDWARDS)?;
    session.message_sign_init(private_key, CKM_EDDSA)?;
    let typed_probe = runtime.block_on(client.sign(request.clone()))?;
    if typed_probe.signature_data.as_ref().map(Vec::len) != Some(ED25519_SIGNATURE_LEN) {
        return Err(BenchError::Setup(
            "typed KMS Sign probe did not return a 64-byte Ed25519 signature".to_owned(),
        ));
    }
    let mut pkcs11_probe = [0_u8; ED25519_SIGNATURE_LEN];
    let pkcs11_probe_len = session.sign_message_into(&message, &mut pkcs11_probe)?;
    if pkcs11_probe_len != ED25519_SIGNATURE_LEN {
        return Err(BenchError::Setup(format!(
            "PKCS#11 Sign probe returned {pkcs11_probe_len} bytes, expected \
         {ED25519_SIGNATURE_LEN}"
        )));
    }

    let mut group = criterion.benchmark_group(GROUP);
    let failures = AtomicUsize::new(0);

    group.bench_function("request-build", |bencher| {
        bencher.iter(|| sign_request(black_box(private_key_id), black_box(&message)));
    });

    group.bench_function("ttlv-json-serialize", |bencher| {
        bencher.iter(|| {
            let result = to_ttlv(black_box(&request))
                .map_err(|e| e.to_string())
                .and_then(|ttlv| serde_json::to_vec(&ttlv).map_err(|e| e.to_string()));
            if result.is_err() {
                failures.fetch_add(1, Ordering::Relaxed);
            }
            result
        });
    });

    group.bench_function("published-full-message-raw-http", |bencher| {
        bencher.to_async(runtime).iter(|| async {
            let result = client
                .client
                .post_bytes(&endpoint, full_body.clone(), "application/json")
                .await;
            if !matches!(&result, Ok(response) if response.status.is_success()) {
                failures.fetch_add(1, Ordering::Relaxed);
            }
            result
        });
    });

    group.bench_function("bare-sign-raw-http", |bencher| {
        bencher.to_async(runtime).iter(|| async {
            let result = client
                .client
                .post_bytes(&endpoint, bare_body.clone(), "application/json")
                .await;
            if !matches!(&result, Ok(response) if response.status.is_success()) {
                failures.fetch_add(1, Ordering::Relaxed);
            }
            result
        });
    });

    group.bench_function("published-full-message-binary-http", |bencher| {
        bencher.to_async(runtime).iter(|| async {
            let response = client
                .client
                .post_bytes(
                    &binary_endpoint,
                    full_binary_body.clone(),
                    "application/octet-stream",
                )
                .await;
            let result = match response {
                Ok(response) if response.status.is_success() => {
                    validate_binary_sign_response(response.bytes())
                }
                Ok(response) => Err(BenchError::Setup(format!(
                    "binary Sign returned HTTP {}",
                    response.status
                ))),
                Err(error) => Err(map_setup_error("binary Sign HTTP request", error)),
            };
            if result.is_err() {
                failures.fetch_add(1, Ordering::Relaxed);
            }
            result
        });
    });

    group.bench_function("response-parse", |bencher| {
        bencher.iter(|| {
            let ttlv = serde_json::from_slice::<TTLV>(black_box(&response_body))
                .map_err(|e| map_setup_error("parse Sign response JSON", e));
            let result = ttlv.and_then(|ttlv| {
                from_ttlv::<SignResponse>(ttlv)
                    .map_err(|e| map_setup_error("parse Sign response TTLV", e))
            });
            if result.is_err() {
                failures.fetch_add(1, Ordering::Relaxed);
            }
            result
        });
    });

    group.bench_function("binary-response-parse", |bencher| {
        bencher.iter(|| {
            let ttlv = TTLV::from_bytes(black_box(&binary_response_body), KmipFlavor::Kmip2)
                .map_err(|e| map_setup_error("parse binary Sign response TTLV", e));
            let result = ttlv.and_then(|ttlv| {
                from_ttlv::<ResponseMessage>(ttlv)
                    .map_err(|e| map_setup_error("deserialize binary Sign response", e))
            });
            if result.is_err() {
                failures.fetch_add(1, Ordering::Relaxed);
            }
            result
        });
    });

    group.bench_function("typed-kms-client-sign", |bencher| {
        bencher.to_async(runtime).iter(|| async {
            let result = client.sign(request.clone()).await;
            if result.is_err() {
                failures.fetch_add(1, Ordering::Relaxed);
            }
            result
        });
    });

    let typed_before_counter = AtomicUsize::new(0);
    group.bench_function("typed-binary-message-sign-before", |bencher| {
        bencher.to_async(runtime).iter(|| async {
            let request = if vary_payload {
                let index =
                    typed_before_counter.fetch_add(1, Ordering::Relaxed) % varying_messages.len();
                sign_request(
                    private_key_id,
                    varying_messages.get(index).unwrap_or(&message),
                )
            } else {
                request.clone()
            };
            let result = client.sign_bytes(request).await.and_then(|response| {
                if response.signature_data.as_ref().map(Vec::len) == Some(ED25519_SIGNATURE_LEN) {
                    Ok(response)
                } else {
                    Err(KmsClientError::ResponseFailed(
                        "binary Sign did not return a 64-byte signature".to_owned(),
                    ))
                }
            });
            if result.is_err() {
                failures.fetch_add(1, Ordering::Relaxed);
            }
            result
        });
    });

    group.bench_function("runtime-block-on-ready", |bencher| {
        bencher.iter(|| {
            black_box(());
            runtime.block_on(std::future::ready(()));
        });
    });

    session.set_sign_profile_enabled(false)?;
    let pkcs11_before_counter = AtomicUsize::new(0);
    group.bench_function("pkcs11-one-call-before", |bencher| {
        bencher.iter(|| {
            let mut signature = [0_u8; ED25519_SIGNATURE_LEN];
            let payload = if vary_payload {
                let index =
                    pkcs11_before_counter.fetch_add(1, Ordering::Relaxed) % varying_messages.len();
                varying_messages.get(index).unwrap_or(&message)
            } else {
                &message
            };
            let result = session.sign_message_into(payload, &mut signature);
            if result.is_err() {
                failures.fetch_add(1, Ordering::Relaxed);
            }
            result
        });
    });

    let typed_after_counter = AtomicUsize::new(0);
    group.bench_function("typed-binary-message-sign-after", |bencher| {
        bencher.to_async(runtime).iter(|| async {
            let request = if vary_payload {
                let index =
                    typed_after_counter.fetch_add(1, Ordering::Relaxed) % varying_messages.len();
                sign_request(
                    private_key_id,
                    varying_messages.get(index).unwrap_or(&message),
                )
            } else {
                request.clone()
            };
            let result = client.sign_bytes(request).await.and_then(|response| {
                if response.signature_data.as_ref().map(Vec::len) == Some(ED25519_SIGNATURE_LEN) {
                    Ok(response)
                } else {
                    Err(KmsClientError::ResponseFailed(
                        "binary Sign did not return a 64-byte signature".to_owned(),
                    ))
                }
            });
            if result.is_err() {
                failures.fetch_add(1, Ordering::Relaxed);
            }
            result
        });
    });

    let pkcs11_after_counter = AtomicUsize::new(0);
    group.bench_function("pkcs11-one-call-after", |bencher| {
        bencher.iter(|| {
            let mut signature = [0_u8; ED25519_SIGNATURE_LEN];
            let payload = if vary_payload {
                let index =
                    pkcs11_after_counter.fetch_add(1, Ordering::Relaxed) % varying_messages.len();
                varying_messages.get(index).unwrap_or(&message)
            } else {
                &message
            };
            let result = session.sign_message_into(payload, &mut signature);
            if result.is_err() {
                failures.fetch_add(1, Ordering::Relaxed);
            }
            result
        });
    });
    session.message_sign_final()?;

    group.bench_function("pkcs11-two-call-fixed-query", |bencher| {
        bencher.iter(|| {
            let result = session.sign_with_length_query(private_key, &message, CKM_EDDSA);
            if result.is_err() {
                failures.fetch_add(1, Ordering::Relaxed);
            }
            result
        });
    });

    group.finish();
    let failure_count = failures.load(Ordering::Relaxed);
    if failure_count > 0 {
        return Err(BenchError::Setup(format!(
            "differential overhead benchmarks observed {failure_count} failed operations"
        )));
    }

    // The legacy comparison tier above clears the classic sign context. Re-arm
    // the reusable v3 message-sign context before collecting internal phases.
    session.message_sign_init(private_key, CKM_EDDSA)?;
    // Collect internal phases in a separate pass so clocks and atomic histogram
    // updates do not contaminate the differential Criterion tiers above.
    session.reset_sign_profile()?;
    session.set_sign_profile_enabled(true)?;
    let profile_result = (0..PROFILE_SAMPLES).try_for_each(|_| {
        let mut signature = [0_u8; ED25519_SIGNATURE_LEN];
        session
            .sign_message_into(&message, &mut signature)
            .map(|_| ())
    });
    session.set_sign_profile_enabled(false)?;
    profile_result?;
    let phases = profile_phases(&session.sign_profile_snapshot()?);
    session.message_sign_final()?;

    Ok(OverheadMetadata {
        algorithm: "eddsa-ed25519",
        payload_bytes: message.len(),
        request_bytes: bare_body.len(),
        response_bytes: response_body.len(),
        binary_request_bytes: full_binary_body.len(),
        binary_response_bytes: binary_response_body.len(),
        varying_payload: vary_payload,
        phases,
    })
}
