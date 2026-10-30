//! Server-side state of KMIP multi-part (streaming) cryptographic operations.
//!
//! KMIP 2.1 §6.1 / 1.4 §4: a client starts a multi-part operation with `Init Indicator = true`,
//! the server answers with an opaque, server-generated `Correlation Value`, the client sends it
//! back with every following part and ends with `Final Indicator = true`.
//!
//! The state lives only in server memory and is:
//! - bound to the operation, the requesting user and the key: any mismatch is reported exactly
//!   like an unknown value (`Invalid Correlation Value`), so a correlation value is useless to
//!   anyone but its creator;
//! - bounded in number (globally and per user), in buffered bytes (per operation, per user and
//!   globally), and expired after an idle timeout or a maximum age;
//! - dropped on the final part, on any processing error, on expiry and when its key is destroyed
//!   or revoked as compromised. Dropping frees the OpenSSL contexts (which cleanse their key
//!   schedules) and zeroizes buffered input; it never happens while the store lock is held.

use std::{
    any::Any,
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::ErrorReason, kmip_2_1::kmip_types::CryptographicParameters,
    },
    cosmian_kms_crypto::crypto::KmsRng,
};
use zeroize::Zeroizing;

use crate::{error::KmsError, result::KResult};

/// Length of the random server-generated Correlation Value.
const CORRELATION_VALUE_LENGTH: usize = 16;

/// Resource limits of a [`MultiPartStore`].
#[derive(Debug, Clone, Copy)]
struct Limits {
    /// Operations open at the same time on the server.
    streams: usize,
    /// Operations open at the same time by one user.
    streams_per_user: usize,
    /// An operation not continued within this delay is discarded.
    idle_timeout: Duration,
    /// An operation is discarded this long after its initial part, however active.
    max_age: Duration,
    /// Input buffered (Sign, Signature Verify) by all operations.
    bytes: usize,
    /// Input buffered by the operations of one user.
    bytes_per_user: usize,
    /// Input buffered by one operation.
    bytes_per_stream: usize,
}

const MIB: usize = 1024 * 1024;

const DEFAULT_LIMITS: Limits = Limits {
    streams: 1024,
    streams_per_user: 64,
    idle_timeout: Duration::from_secs(300),
    max_age: Duration::from_secs(3600),
    bytes: 256 * MIB,
    bytes_per_user: 64 * MIB,
    bytes_per_stream: 16 * MIB,
};

/// Position of a request in a (possibly) multi-part operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Part<'a> {
    /// Single-part request: no Correlation Value and not (`Init` without `Final`).
    Single,
    /// First part: `Init Indicator = true`, no `Final Indicator`, no Correlation Value.
    Init,
    /// Intermediate part carrying the Correlation Value.
    Next(&'a [u8]),
    /// Final part carrying the Correlation Value and `Final Indicator = true`.
    Last(&'a [u8]),
}

impl<'a> Part<'a> {
    /// Classify a request from its `Init Indicator`, `Final Indicator` and `Correlation Value`.
    ///
    /// KMIP 2.1 §6.1: a request with both indicators set and no Correlation Value is single-part.
    pub(crate) fn classify(
        init_indicator: Option<bool>,
        final_indicator: Option<bool>,
        correlation_value: Option<&'a [u8]>,
    ) -> KResult<Self> {
        let init = init_indicator == Some(true);
        let last = final_indicator == Some(true);
        match correlation_value {
            None if init && !last => Ok(Self::Init),
            None => Ok(Self::Single),
            Some(_) if init => Err(KmsError::Kmip21Error(
                ErrorReason::Invalid_Field,
                "the Init Indicator cannot be combined with a Correlation Value".to_owned(),
            )),
            Some(cv) if last => Ok(Self::Last(cv)),
            Some(cv) => Ok(Self::Next(cv)),
        }
    }

    /// Whether this request completes the operation (single-part or final part).
    pub(crate) const fn is_last(&self) -> bool {
        matches!(self, Self::Single | Self::Last(_))
    }

    /// Whether this request belongs to a multi-part operation.
    pub(crate) const fn is_multi_part(&self) -> bool {
        !matches!(self, Self::Single)
    }
}

/// Reject a multi-part request for keys served by a crypto oracle (HSM), which cannot hold
/// streaming state across requests (KMIP 2.1 §6.1: multi-part support is optional).
pub(crate) fn reject_multi_part_for_oracle(op: &str, part: Part<'_>) -> KResult<()> {
    if part.is_multi_part() {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Feature_Not_Supported,
            format!("{op}: multi-part operations are not supported for HSM keys"),
        ));
    }
    Ok(())
}

/// Identifies who may continue a multi-part operation.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamOwner<'a> {
    /// The operation name (e.g. `"Encrypt"`).
    pub(crate) op: &'static str,
    /// The authenticated user.
    pub(crate) user: &'a str,
    /// The key Unique Identifier, empty for key-less operations (Hash).
    pub(crate) key_uid: &'a str,
}

struct Stream {
    op: &'static str,
    user: String,
    key_uid: String,
    created: Instant,
    last_used: Instant,
    state: Box<dyn Any + Send>,
}

impl Stream {
    fn is_owned_by(&self, owner: &StreamOwner<'_>) -> bool {
        self.op == owner.op && self.user == owner.user && self.key_uid == owner.key_uid
    }

    fn is_expired(&self, limits: &Limits) -> bool {
        self.last_used.elapsed() >= limits.idle_timeout || self.created.elapsed() >= limits.max_age
    }
}

/// Bytes buffered by open multi-part operations: in total and per user.
#[derive(Debug)]
struct ByteBudget {
    limits: Limits,
    used: Mutex<(usize, HashMap<String, usize>)>,
}

impl ByteBudget {
    fn used(&self) -> MutexGuard<'_, (usize, HashMap<String, usize>)> {
        // The counters stay consistent if a holder panicked: no update spans a panic point.
        self.used.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reserve `n` more bytes for `user` whose stream already holds `stream_bytes`.
    fn charge(&self, user: &str, stream_bytes: usize, n: usize, op: &str) -> KResult<()> {
        let mut used = self.used();
        let (total, per_user) = &mut *used;
        let user_bytes = per_user.get(user).copied().unwrap_or_default();
        let limits = &self.limits;
        if stream_bytes.saturating_add(n) > limits.bytes_per_stream
            || user_bytes.saturating_add(n) > limits.bytes_per_user
            || total.saturating_add(n) > limits.bytes
        {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Server_Limit_Exceeded,
                format!(
                    "{op}: multi-part input exceeds the server limits ({} bytes per operation, \
                     {} bytes per user, {} bytes in total)",
                    limits.bytes_per_stream, limits.bytes_per_user, limits.bytes
                ),
            ));
        }
        *total += n;
        *per_user.entry(user.to_owned()).or_default() += n;
        Ok(())
    }

    fn release(&self, user: &str, n: usize) {
        let mut used = self.used();
        let (total, per_user) = &mut *used;
        *total = total.saturating_sub(n);
        if let Some(user_bytes) = per_user.get_mut(user) {
            *user_bytes = user_bytes.saturating_sub(n);
            if *user_bytes == 0 {
                per_user.remove(user);
            }
        }
    }
}

/// Input of a multi-part operation that needs the whole message (Sign, Signature Verify),
/// charged against the store's byte budgets until dropped. Created by
/// [`MultiPartStore::buffer`], filled by [`append_bounded`].
pub(crate) struct BoundedBuffer {
    data: Zeroizing<Vec<u8>>,
    charged: usize,
    user: String,
    budget: Arc<ByteBudget>,
}

impl BoundedBuffer {
    /// Move the buffered input out; the bytes stay charged until the buffer is dropped.
    pub(crate) fn take(&mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut *self.data))
    }
}

impl std::ops::Deref for BoundedBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for BoundedBuffer {
    fn drop(&mut self) {
        self.budget.release(&self.user, self.charged);
    }
}

/// Append `data` to a multi-part input buffer within the per-operation, per-user and global
/// byte budgets (`Server Limit Exceeded` otherwise).
pub(crate) fn append_bounded(buffer: &mut BoundedBuffer, data: &[u8], op: &str) -> KResult<()> {
    buffer
        .budget
        .charge(&buffer.user, buffer.charged, data.len(), op)?;
    buffer.charged += data.len();
    buffer.data.extend_from_slice(data);
    Ok(())
}

/// Request fields fixed by the initial part of a multi-part Encrypt or Decrypt (KMIP 2.1
/// Table 196: the Authenticated Encryption Additional Data MUST be supplied on the initial
/// request). A later part may omit or repeat them; a different value is rejected with
/// `Invalid Field` instead of being silently ignored.
pub(crate) struct FixedFields {
    cryptographic_parameters: Option<CryptographicParameters>,
    iv: Vec<u8>,
    aad: Vec<u8>,
}

impl FixedFields {
    /// Record the initial part's parameters, its effective IV/nonce and AAD.
    pub(crate) fn new(cp: Option<&CryptographicParameters>, iv: &[u8], aad: &[u8]) -> Self {
        Self {
            cryptographic_parameters: cp.cloned(),
            iv: iv.to_vec(),
            aad: aad.to_vec(),
        }
    }

    /// The initial part's Cryptographic Parameters.
    pub(crate) const fn cryptographic_parameters(&self) -> Option<&CryptographicParameters> {
        self.cryptographic_parameters.as_ref()
    }

    /// Reject a part whose parameters, IV/nonce or AAD differ from the initial part's.
    pub(crate) fn check(
        &self,
        op: &str,
        cp: Option<&CryptographicParameters>,
        iv: Option<&[u8]>,
        aad: Option<&[u8]>,
    ) -> KResult<()> {
        if cp.is_some_and(|cp| self.cryptographic_parameters.as_ref() != Some(cp))
            || iv.is_some_and(|iv| iv != self.iv.as_slice())
            || aad.is_some_and(|aad| aad != self.aad.as_slice())
        {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Invalid_Field,
                format!(
                    "{op}: the Cryptographic Parameters, IV/Counter/Nonce and Authenticated \
                     Encryption Additional Data are fixed by the initial part of a multi-part \
                     operation"
                ),
            ));
        }
        Ok(())
    }
}

/// In-memory store of open multi-part operations, keyed by Correlation Value.
pub(crate) struct MultiPartStore {
    streams: Mutex<HashMap<Vec<u8>, Stream>>,
    limits: Limits,
    budget: Arc<ByteBudget>,
}

impl Default for MultiPartStore {
    fn default() -> Self {
        Self::with_limits(DEFAULT_LIMITS)
    }
}

fn invalid_correlation_value() -> KmsError {
    KmsError::Kmip21Error(
        ErrorReason::Invalid_Correlation_Value,
        "unknown or expired Correlation Value".to_owned(),
    )
}

impl MultiPartStore {
    fn with_limits(limits: Limits) -> Self {
        Self {
            streams: Mutex::new(HashMap::new()),
            limits,
            budget: Arc::new(ByteBudget {
                limits,
                used: Mutex::new((0, HashMap::new())),
            }),
        }
    }

    /// Lock the store after moving its expired streams into `evicted`. The caller declares
    /// `evicted` before the guard, so the streams are dropped after the lock is released.
    fn lock(&self, evicted: &mut Vec<Stream>) -> MutexGuard<'_, HashMap<Vec<u8>, Stream>> {
        // The map stays consistent if a holder panicked: no update spans a panic point.
        let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
        let limits = self.limits;
        evict(&mut streams, evicted, |s| s.is_expired(&limits));
        streams
    }

    /// An empty input buffer charged to `user`, for operations that need the whole message.
    pub(crate) fn buffer(&self, user: &str) -> BoundedBuffer {
        BoundedBuffer {
            data: Zeroizing::new(Vec::new()),
            charged: 0,
            user: user.to_owned(),
            budget: Arc::clone(&self.budget),
        }
    }

    /// Abort every multi-part operation using the key `key_uid`. Called when the key is
    /// destroyed or revoked as compromised, so its key schedule does not outlive it.
    pub(crate) fn purge_key(&self, key_uid: &str) {
        let mut evicted = Vec::new();
        let mut streams = self.lock(&mut evicted);
        evict(&mut streams, &mut evicted, |s| s.key_uid == key_uid);
        drop(streams);
    }

    /// Run one part of an operation.
    ///
    /// The state is created by `init` for single-part and initial requests, or taken from the
    /// store for continuations. `process(state, is_last)` handles this part's input. Unless the
    /// part is the last one, the state is then kept and its Correlation Value returned.
    /// On error the state is dropped, which aborts the multi-part operation.
    pub(crate) fn run<S: Any + Send, T>(
        &self,
        rng: &KmsRng,
        part: Part<'_>,
        owner: StreamOwner<'_>,
        init: impl FnOnce() -> KResult<S>,
        process: impl FnOnce(&mut S, bool) -> KResult<T>,
    ) -> KResult<(T, Option<Vec<u8>>)> {
        let (mut state, created) = match part {
            Part::Single | Part::Init => (init()?, Instant::now()),
            Part::Next(cv) | Part::Last(cv) => self.take(cv, owner)?,
        };
        let output = process(&mut state, part.is_last())?;
        let correlation_value = match part {
            Part::Single | Part::Last(_) => None,
            Part::Init => Some(self.open(rng, owner, state)?),
            Part::Next(cv) => {
                let mut evicted = Vec::new();
                self.lock(&mut evicted)
                    .insert(cv.to_vec(), new_stream(owner, created, state));
                Some(cv.to_vec())
            }
        };
        Ok((output, correlation_value))
    }

    fn take<S: Any + Send>(&self, cv: &[u8], owner: StreamOwner<'_>) -> KResult<(S, Instant)> {
        // Server-generated values have a fixed length: anything else is unknown, and is
        // rejected before hashing it under the lock.
        if cv.len() != CORRELATION_VALUE_LENGTH {
            return Err(invalid_correlation_value());
        }
        let mut evicted = Vec::new();
        let mut streams = self.lock(&mut evicted);
        if !streams.get(cv).is_some_and(|s| s.is_owned_by(&owner)) {
            return Err(invalid_correlation_value());
        }
        let stream = streams.remove(cv).ok_or_else(invalid_correlation_value)?;
        drop(streams);
        let created = stream.created;
        stream
            .state
            .downcast::<S>()
            .map(|s| (*s, created))
            .map_err(|_e| invalid_correlation_value())
    }

    fn open<S: Any + Send>(
        &self,
        rng: &KmsRng,
        owner: StreamOwner<'_>,
        state: S,
    ) -> KResult<Vec<u8>> {
        let mut cv = vec![0_u8; CORRELATION_VALUE_LENGTH];
        rng.fill_bytes(&mut cv)?;
        let mut evicted = Vec::new();
        // One critical section for the limit check and the insertion, so concurrent initial
        // parts cannot overshoot the limits.
        let mut streams = self.lock(&mut evicted);
        let per_user = streams.values().filter(|s| s.user == owner.user).count();
        if streams.len() >= self.limits.streams || per_user >= self.limits.streams_per_user {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Server_Limit_Exceeded,
                format!(
                    "{}: too many multi-part operations in progress; finish or let some expire \
                     first",
                    owner.op
                ),
            ));
        }
        streams.insert(cv.clone(), new_stream(owner, Instant::now(), state));
        Ok(cv)
    }
}

/// Move the streams matching `pred` from `streams` into `out`.
// shortcut: collects keys because `HashMap::extract_if` needs Rust 1.88 (MSRV is 1.87).
fn evict(
    streams: &mut HashMap<Vec<u8>, Stream>,
    out: &mut Vec<Stream>,
    pred: impl Fn(&Stream) -> bool,
) {
    let keys: Vec<Vec<u8>> = streams
        .iter()
        .filter(|(_, s)| pred(s))
        .map(|(cv, _)| cv.clone())
        .collect();
    out.extend(keys.iter().filter_map(|cv| streams.remove(cv)));
}

fn new_stream<S: Any + Send>(owner: StreamOwner<'_>, created: Instant, state: S) -> Stream {
    Stream {
        op: owner.op,
        user: owner.user.to_owned(),
        key_uid: owner.key_uid.to_owned(),
        created,
        last_used: Instant::now(),
        state: Box::new(state),
    }
}

#[cfg(test)]
#[expect(clippy::panic_in_result_fn)]
mod tests {
    use super::*;

    const ALICE: StreamOwner<'static> = StreamOwner {
        op: "Hash",
        user: "alice",
        key_uid: "k1",
    };

    fn reason(e: &KmsError) -> Option<ErrorReason> {
        match e {
            KmsError::Kmip21Error(r, _) => Some(*r),
            _ => None,
        }
    }

    /// Push `data` into the stream state; the last part returns everything pushed so far.
    fn sum(
        store: &MultiPartStore,
        rng: &KmsRng,
        part: Part<'_>,
        owner: StreamOwner<'_>,
        data: u8,
    ) -> KResult<(Vec<u8>, Option<Vec<u8>>)> {
        store.run(
            rng,
            part,
            owner,
            || Ok(Vec::<u8>::new()),
            |s, last| {
                s.push(data);
                Ok(if last { s.clone() } else { Vec::new() })
            },
        )
    }

    #[test]
    fn classify_parts() -> KResult<()> {
        assert_eq!(Part::classify(None, None, None)?, Part::Single);
        assert_eq!(Part::classify(Some(true), Some(true), None)?, Part::Single);
        assert_eq!(Part::classify(Some(true), None, None)?, Part::Init);
        assert_eq!(Part::classify(None, None, Some(b"x"))?, Part::Next(b"x"));
        assert_eq!(
            Part::classify(None, Some(true), Some(b"x"))?,
            Part::Last(b"x")
        );
        let err = Part::classify(Some(true), None, Some(b"x")).unwrap_err();
        assert_eq!(reason(&err), Some(ErrorReason::Invalid_Field));
        Ok(())
    }

    #[test]
    fn stream_lifecycle_and_isolation() -> KResult<()> {
        let rng = KmsRng::new();
        let store = MultiPartStore::default();
        let (_, cv) = sum(&store, &rng, Part::Init, ALICE, 1)?;
        let cv = cv.unwrap();
        assert_eq!(cv.len(), CORRELATION_VALUE_LENGTH);

        // Another user, operation or key cannot continue it, and cannot tell it exists.
        for owner in [
            StreamOwner {
                user: "bob",
                ..ALICE
            },
            StreamOwner { op: "MAC", ..ALICE },
            StreamOwner {
                key_uid: "k2",
                ..ALICE
            },
        ] {
            let err = sum(&store, &rng, Part::Next(&cv), owner, 9).unwrap_err();
            assert_eq!(reason(&err), Some(ErrorReason::Invalid_Correlation_Value));
        }
        let (_, again) = sum(&store, &rng, Part::Next(&cv), ALICE, 2)?;
        assert_eq!(again.as_deref(), Some(cv.as_slice()));
        let (out, none) = sum(&store, &rng, Part::Last(&cv), ALICE, 3)?;
        assert_eq!(out, vec![1, 2, 3]);
        assert!(none.is_none());
        // The final part consumed the state.
        let err = sum(&store, &rng, Part::Last(&cv), ALICE, 4).unwrap_err();
        assert_eq!(reason(&err), Some(ErrorReason::Invalid_Correlation_Value));
        Ok(())
    }

    #[test]
    fn stream_limits_and_expiry() -> KResult<()> {
        let rng = KmsRng::new();
        let store = MultiPartStore::with_limits(Limits {
            streams: 2,
            streams_per_user: 1,
            ..DEFAULT_LIMITS
        });
        sum(&store, &rng, Part::Init, ALICE, 1)?;
        let err = sum(&store, &rng, Part::Init, ALICE, 1).unwrap_err();
        assert_eq!(reason(&err), Some(ErrorReason::Server_Limit_Exceeded));
        sum(
            &store,
            &rng,
            Part::Init,
            StreamOwner {
                user: "bob",
                ..ALICE
            },
            1,
        )?;
        let err = sum(
            &store,
            &rng,
            Part::Init,
            StreamOwner {
                user: "carol",
                ..ALICE
            },
            1,
        )
        .unwrap_err();
        assert_eq!(reason(&err), Some(ErrorReason::Server_Limit_Exceeded));

        let store = MultiPartStore::with_limits(Limits {
            idle_timeout: Duration::ZERO,
            ..DEFAULT_LIMITS
        });
        let (_, cv) = sum(&store, &rng, Part::Init, ALICE, 1)?;
        let err = sum(&store, &rng, Part::Last(&cv.unwrap()), ALICE, 2).unwrap_err();
        assert_eq!(reason(&err), Some(ErrorReason::Invalid_Correlation_Value));

        // Activity does not extend a stream past its maximum age.
        let store = MultiPartStore::with_limits(Limits {
            max_age: Duration::ZERO,
            ..DEFAULT_LIMITS
        });
        let (_, cv) = sum(&store, &rng, Part::Init, ALICE, 1)?;
        let err = sum(&store, &rng, Part::Next(&cv.unwrap()), ALICE, 2).unwrap_err();
        assert_eq!(reason(&err), Some(ErrorReason::Invalid_Correlation_Value));

        // A Correlation Value of the wrong length is unknown.
        let err = sum(&store, &rng, Part::Next(&[0; 64]), ALICE, 2).unwrap_err();
        assert_eq!(reason(&err), Some(ErrorReason::Invalid_Correlation_Value));
        Ok(())
    }

    #[test]
    fn purge_key_aborts_its_streams() -> KResult<()> {
        let rng = KmsRng::new();
        let store = MultiPartStore::default();
        let (_, cv1) = sum(&store, &rng, Part::Init, ALICE, 1)?;
        let other = StreamOwner {
            key_uid: "k2",
            ..ALICE
        };
        let (_, cv2) = sum(&store, &rng, Part::Init, other, 1)?;
        store.purge_key("k1");
        let err = sum(&store, &rng, Part::Last(&cv1.unwrap()), ALICE, 2).unwrap_err();
        assert_eq!(reason(&err), Some(ErrorReason::Invalid_Correlation_Value));
        sum(&store, &rng, Part::Last(&cv2.unwrap()), other, 2)?;
        Ok(())
    }

    #[test]
    fn processing_error_aborts_stream() -> KResult<()> {
        let rng = KmsRng::new();
        let store = MultiPartStore::default();
        let (_, cv) = sum(&store, &rng, Part::Init, ALICE, 1)?;
        let cv = cv.unwrap();
        let failed: KResult<((), Option<Vec<u8>>)> = store.run(
            &rng,
            Part::Next(&cv),
            ALICE,
            || Ok(Vec::<u8>::new()),
            |_, _| Err(KmsError::InvalidRequest("boom".to_owned())),
        );
        failed.unwrap_err();
        let err = sum(&store, &rng, Part::Last(&cv), ALICE, 2).unwrap_err();
        assert_eq!(reason(&err), Some(ErrorReason::Invalid_Correlation_Value));
        Ok(())
    }

    #[test]
    fn buffered_bytes_are_bounded_and_released() {
        let store = MultiPartStore::with_limits(Limits {
            bytes: 8,
            bytes_per_user: 6,
            bytes_per_stream: 4,
            ..DEFAULT_LIMITS
        });
        let over =
            |r: KResult<()>| reason(&r.unwrap_err()) == Some(ErrorReason::Server_Limit_Exceeded);
        // Per stream.
        let mut a = store.buffer("alice");
        append_bounded(&mut a, b"1234", "Sign").unwrap();
        assert!(over(append_bounded(&mut a, b"5", "Sign")));
        assert_eq!(&*a, b"1234");
        // Per user.
        let mut b = store.buffer("alice");
        append_bounded(&mut b, b"12", "Sign").unwrap();
        assert!(over(append_bounded(&mut b, b"3", "Sign")));
        // In total.
        let mut c = store.buffer("bob");
        append_bounded(&mut c, b"12", "Sign").unwrap();
        assert!(over(append_bounded(&mut c, b"3", "Sign")));
        // Dropping a buffer releases its bytes, even after its data was taken.
        assert_eq!(a.take().as_slice(), b"1234");
        drop(a);
        append_bounded(&mut c, b"34", "Sign").unwrap();
        append_bounded(&mut b, b"34", "Sign").unwrap();
        drop((b, c));
        assert_eq!(store.budget.used().0, 0);
        assert!(store.budget.used().1.is_empty());
    }
}
