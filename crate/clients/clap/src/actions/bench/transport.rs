//! Transport abstraction shared by the KMIP JSON and binary-TTLV benchmarks.
//!
//! Both transports wrap a KMIP [`Operation`] in a [`RequestMessage`] and POST
//! it; they differ **only** in the serialization format and the target
//! endpoint:
//! - [`Transport::Json`]  — JSON-serialized TTLV to `POST /kmip/2_1`
//!   (`application/json`)
//! - [`Transport::Bytes`] — binary TTLV to `POST /kmip`
//!   (`application/octet-stream`)
//!
//! Keeping the request construction and response handling in one place lets the
//! benchmark bodies be written once and parameterized by the transport, so the
//! two protocols share the same source except serialization.

use std::{
    cell::Cell,
    time::{Duration, Instant},
};

use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::{
        kmip_0::{
            kmip_messages::{
                RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            },
            kmip_types::ProtocolVersion,
        },
        ttlv::{KmipFlavor, to_ttlv},
    },
    kmip_2_1::{kmip_messages::RequestMessageBatchItem, kmip_operations::Operation},
};
use criterion::BenchmarkId;
use tokio::runtime::Runtime;

thread_local! {
    /// Maximum wall-clock time budget for a single benchmark group.
    static MAX_GROUP_TIME: Cell<Option<Duration>> = const { Cell::new(None) };
    /// Instant at which the current benchmark group started.
    static GROUP_START: Cell<Option<Instant>> = const { Cell::new(None) };
}

/// Set the per-group wall-clock time budget (call once before running benchmarks).
///
/// When set, [`bench_op`], [`bench_op_id`] and [`bench_message_id`] skip any
/// remaining benchmarks in a group once the elapsed time since the group was
/// created via [`timed_group`] exceeds `limit`.
pub(super) fn set_max_group_time(limit: Option<Duration>) {
    MAX_GROUP_TIME.with(|c| c.set(limit));
}

/// Create a criterion benchmark group and (re)start its per-group timer.
pub(super) fn timed_group(
    c: &mut criterion::Criterion,
    name: impl Into<String>,
) -> criterion::BenchmarkGroup<'_, criterion::measurement::WallTime> {
    GROUP_START.with(|s| s.set(Some(Instant::now())));
    c.benchmark_group(name)
}

/// Returns `true` once the current group has exhausted its time budget.
fn group_over_budget() -> bool {
    let Some(limit) = MAX_GROUP_TIME.with(Cell::get) else {
        return false;
    };
    GROUP_START
        .with(Cell::get)
        .is_some_and(|start| start.elapsed() >= limit)
}

/// Serialization strategy and endpoint for KMIP benchmarks.
#[derive(Clone, Copy)]
pub(super) enum Transport {
    /// KMIP over JSON-serialized TTLV (`POST /kmip/2_1`, `application/json`).
    Json,
    /// KMIP over binary TTLV wire format (`POST /kmip`, `application/octet-stream`).
    Bytes,
}

impl Transport {
    /// Protocol slug used as the criterion group-name prefix (e.g. `ttlv-json`).
    pub(super) const fn slug(self) -> &'static str {
        match self {
            Self::Json => "ttlv-json",
            Self::Bytes => "ttlv-bytes",
        }
    }

    /// Target endpoint URL for this transport.
    fn url(self, client: &KmsClient) -> String {
        match self {
            Self::Json => format!("{}/kmip/2_1", client.client.server_url),
            Self::Bytes => format!("{}/kmip", client.client.server_url),
        }
    }

    /// HTTP `Content-Type` header value for this transport.
    const fn content_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Bytes => "application/octet-stream",
        }
    }

    /// Serialize a `RequestMessage` to the wire body for this transport.
    fn serialize(self, msg: &RequestMessage) -> Vec<u8> {
        let ttlv = to_ttlv(msg).expect("TTLV serialization");
        match self {
            Self::Json => serde_json::to_vec(&ttlv).expect("JSON serialization"),
            Self::Bytes => ttlv
                .to_bytes(KmipFlavor::Kmip2)
                .expect("Binary TTLV serialization"),
        }
    }
}

/// Wrap a single KMIP operation in a `RequestMessage` ready for TTLV serialization.
///
/// The KMIP wire formats require a `RequestMessage` at the top level; bare
/// operation structs do not have a registered binary tag and would produce an
/// "Unknown tag" error. Wrapping the operation identically for both transports
/// makes them exercise the same server-side `message()` dispatch path.
pub(super) fn make_wire_request(op: Operation) -> RequestMessage {
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
            RequestMessageBatchItem::new(op),
        )],
    }
}

/// Serialize a `RequestMessage` to binary TTLV bytes for the `/kmip` endpoint.
pub(super) fn to_wire_bytes(msg: &RequestMessage) -> Vec<u8> {
    let ttlv = to_ttlv(msg).expect("TTLV serialization");
    ttlv.to_bytes(KmipFlavor::Kmip2)
        .expect("Binary TTLV serialization")
}

/// Check whether a binary TTLV response from `/kmip` (octet-stream) indicates success.
///
/// The binary KMIP endpoint **always** returns HTTP 200 even on KMIP-level
/// errors; the actual result is encoded inside the binary TTLV response body.
///
/// Uses a zero-allocation byte scan instead of full TTLV tree deserialisation.
/// The KMIP binary format encodes `ResultStatus` as a fixed 16-byte TLV:
///
/// ```text
/// 42 00 7F  05  00 00 00 04  00 00 00 00  00 00 00 00
/// -tag----  ty  --length--   ---value--   --padding--
/// ResultSt  Enum  4 bytes     0=Success
/// ```
///
/// Scanning for the 8-byte header and checking the 4-byte value costs ~100 ns
/// with zero heap allocations, compared to ~3-5 us for the full-tree path
/// (`TTLV::from_bytes` + `from_ttlv::<ResponseMessage>`).
pub(super) fn wire_response_ok(bytes: &[u8]) -> bool {
    // Tag=0x42007F (ResultStatus), Type=0x05 (Enumeration), Length=4
    const RESULT_STATUS_HEADER: [u8; 8] = [0x42, 0x00, 0x7F, 0x05, 0x00, 0x00, 0x00, 0x04];
    // Value 0x00000000 == Success (KMIP `ResultStatusEnumeration::Success = 0`).
    bytes
        .windows(8)
        .position(|w| w == RESULT_STATUS_HEADER)
        .and_then(|i| bytes.get(i + 8..i + 12))
        .is_some_and(|v| v == [0x00, 0x00, 0x00, 0x00])
}

/// Serialize a single operation into `(url, body, content_type)` for posting.
fn prepare_op(
    transport: Transport,
    client: &KmsClient,
    op: Operation,
) -> (String, Vec<u8>, &'static str) {
    (
        transport.url(client),
        transport.serialize(&make_wire_request(op)),
        transport.content_type(),
    )
}

/// Serialize a pre-built `RequestMessage` into `(url, body, content_type)`.
fn prepare_message(
    transport: Transport,
    client: &KmsClient,
    msg: &RequestMessage,
) -> (String, Vec<u8>, &'static str) {
    (
        transport.url(client),
        transport.serialize(msg),
        transport.content_type(),
    )
}

/// Benchmark a single KMIP operation under a plain (unparameterized) label.
///
/// The operation is serialized **once**; every criterion iteration then measures
/// the cost of sending the identical body (cloned per iteration).
pub(super) fn bench_op(
    group: &mut criterion::BenchmarkGroup<criterion::measurement::WallTime>,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
    name: impl Into<String>,
    op: Operation,
) {
    if group_over_budget() {
        return;
    }
    let (url, body, content_type) = prepare_op(transport, client, op);
    group.bench_function(name.into(), |b| {
        b.to_async(rt)
            .iter(|| client.client.post_bytes(&url, body.clone(), content_type));
    });
}

/// Benchmark a single KMIP operation under a parameterized [`BenchmarkId`].
pub(super) fn bench_op_id(
    group: &mut criterion::BenchmarkGroup<criterion::measurement::WallTime>,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
    id: BenchmarkId,
    op: Operation,
) {
    if group_over_budget() {
        return;
    }
    let (url, body, content_type) = prepare_op(transport, client, op);
    group.bench_function(id, |b| {
        b.to_async(rt)
            .iter(|| client.client.post_bytes(&url, body.clone(), content_type));
    });
}

/// Benchmark a pre-built `RequestMessage` under a parameterized [`BenchmarkId`].
pub(super) fn bench_message_id(
    group: &mut criterion::BenchmarkGroup<criterion::measurement::WallTime>,
    client: &KmsClient,
    rt: &Runtime,
    transport: Transport,
    id: BenchmarkId,
    msg: &RequestMessage,
) {
    if group_over_budget() {
        return;
    }
    let (url, body, content_type) = prepare_message(transport, client, msg);
    group.bench_function(id, |b| {
        b.to_async(rt)
            .iter(|| client.client.post_bytes(&url, body.clone(), content_type));
    });
}
