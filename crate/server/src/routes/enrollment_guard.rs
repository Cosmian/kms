//! Abuse controls shared by the EST and SCEP endpoints.
//!
//! Enrollment endpoints are reachable before the client is authenticated and the secrets they
//! check (EST Basic bootstrap password, SCEP challenge) are long-lived and shared, so three
//! controls apply on top of the optional global `rate_limit_per_second`:
//!
//! - a per-client lockout with exponential back-off after repeated failed authentications,
//! - a replay cache for SCEP messages that already passed authentication,
//! - a cap on the number of enrollments processed concurrently (each one costs RSA private-key
//!   operations and several database reads).
//!
//! All state is in memory and bounded: it is lost on restart, which at worst lets an attacker
//! restart a guessing sequence after the operator restarted the server.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

use tokio::sync::{Semaphore, SemaphorePermit};

/// Failed authentications from one client before it is locked out.
const MAX_FAILURES: u32 = 10;
/// A client that stays quiet this long starts again from zero failures.
const FAILURE_RESET: Duration = Duration::from_secs(3600);
/// First lockout; it doubles with every further failure, up to [`MAX_LOCKOUT`].
const BASE_LOCKOUT: Duration = Duration::from_secs(30);
const MAX_LOCKOUT: Duration = Duration::from_secs(3600);
/// Distinct clients tracked at once. When the table is full the quietest client that is not
/// locked out is forgotten; if every entry is a live lockout nothing is added. A client is
/// never lumped together with others, so an attacker rotating source addresses cannot lock
/// out anybody else.
const MAX_TRACKED_CLIENTS: usize = 10_000;
/// How long an authenticated SCEP message is remembered.
const REPLAY_TTL: Duration = Duration::from_secs(3600);
/// Remembered messages. Only authenticated messages are stored, so the table grows with the
/// legitimate issuance rate; when it is full the oldest message is forgotten, which only
/// matters to a replay of a message older than every one of the last 100 000.
const MAX_REPLAY_ENTRIES: usize = 100_000;
/// Enrollments processed at the same time.
const MAX_CONCURRENT_ENROLLMENTS: usize = 16;

/// Network prefix that identifies one IPv6 client: an end site owns at least a /64 and can
/// pick any address in it, so a per-address lockout would be free to evade.
const IPV6_CLIENT_PREFIX: u32 = 64;
/// Client address used when the transport gives none (in-process requests).
pub(crate) const UNKNOWN_CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

#[derive(Default)]
struct ClientState {
    failures: u32,
    last_failure: Option<Instant>,
    locked_until: Option<Instant>,
}

/// In-memory enrollment abuse controls; one instance lives in [`crate::core::KMS`].
pub(crate) struct EnrollmentGuard {
    clients: Mutex<HashMap<IpAddr, ClientState>>,
    replays: Mutex<HashMap<[u8; 32], Instant>>,
    permits: Semaphore,
}

impl Default for EnrollmentGuard {
    fn default() -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
            replays: Mutex::new(HashMap::new()),
            permits: Semaphore::new(MAX_CONCURRENT_ENROLLMENTS),
        }
    }
}

/// The table key of `client`: IPv4-mapped IPv6 addresses count as IPv4, IPv6 addresses as their
/// /64 prefix.
fn client_key(client: IpAddr) -> IpAddr {
    match client.to_canonical() {
        IpAddr::V6(v6) => {
            let mask = u128::MAX << (128 - IPV6_CLIENT_PREFIX);
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
        v4 @ IpAddr::V4(_) => v4,
    }
}

impl EnrollmentGuard {
    /// Remaining lockout of `client`, if it is locked out.
    pub(crate) fn locked_for(&self, client: IpAddr) -> Option<Duration> {
        self.locked_for_at(client, Instant::now())
    }

    fn locked_for_at(&self, client: IpAddr, now: Instant) -> Option<Duration> {
        let clients = self.clients.lock().unwrap_or_else(PoisonError::into_inner);
        clients
            .get(&client_key(client))?
            .locked_until
            .and_then(|until| until.checked_duration_since(now))
            .filter(|remaining| !remaining.is_zero())
    }

    /// Count one failed authentication of `client`.
    pub(crate) fn record_failure(&self, client: IpAddr) {
        self.record_failure_at(client, Instant::now());
    }

    fn record_failure_at(&self, client: IpAddr, now: Instant) {
        let key = client_key(client);
        let mut clients = self.clients.lock().unwrap_or_else(PoisonError::into_inner);
        if !clients.contains_key(&key) && clients.len() >= MAX_TRACKED_CLIENTS {
            clients.retain(|_, s| {
                s.locked_until.is_some_and(|u| u > now)
                    || s.last_failure
                        .is_some_and(|t| now.saturating_duration_since(t) < FAILURE_RESET)
            });
            if clients.len() >= MAX_TRACKED_CLIENTS {
                let quietest = clients
                    .iter()
                    .filter(|(_, s)| s.locked_until.is_none_or(|u| u <= now))
                    .min_by_key(|(_, s)| s.last_failure)
                    .map(|(ip, _)| *ip);
                match quietest {
                    Some(ip) => {
                        clients.remove(&ip);
                    }
                    None => return,
                }
            }
        }
        let state = clients.entry(key).or_default();
        if state
            .last_failure
            .is_some_and(|t| now.saturating_duration_since(t) >= FAILURE_RESET)
        {
            *state = ClientState::default();
        }
        state.failures = state.failures.saturating_add(1);
        state.last_failure = Some(now);
        if state.failures >= MAX_FAILURES {
            let doublings = (state.failures - MAX_FAILURES).min(7);
            let lockout = BASE_LOCKOUT.saturating_mul(1 << doublings).min(MAX_LOCKOUT);
            state.locked_until = Some(now + lockout);
        }
    }

    /// Forget the failures of `client` after a successful authentication.
    pub(crate) fn record_success(&self, client: IpAddr) {
        let mut clients = self.clients.lock().unwrap_or_else(PoisonError::into_inner);
        clients.remove(&client_key(client));
    }

    /// Remember an authenticated message. `false` when it was already seen within the TTL (a
    /// replay).
    pub(crate) fn register_message(&self, fingerprint: [u8; 32]) -> bool {
        self.register_message_at(fingerprint, Instant::now())
    }

    fn register_message_at(&self, fingerprint: [u8; 32], now: Instant) -> bool {
        let mut replays = self.replays.lock().unwrap_or_else(PoisonError::into_inner);
        if replays
            .get(&fingerprint)
            .is_some_and(|seen| now.saturating_duration_since(*seen) < REPLAY_TTL)
        {
            return false;
        }
        if replays.len() >= MAX_REPLAY_ENTRIES {
            replays.retain(|_, seen| now.saturating_duration_since(*seen) < REPLAY_TTL);
            if replays.len() >= MAX_REPLAY_ENTRIES {
                let oldest = replays
                    .iter()
                    .min_by_key(|(_, seen)| **seen)
                    .map(|(k, _)| *k);
                if let Some(oldest) = oldest {
                    replays.remove(&oldest);
                }
            }
        }
        replays.insert(fingerprint, now);
        true
    }

    /// Reserve one of the concurrent enrollment slots; `None` when all are busy.
    pub(crate) fn try_begin(&self) -> Option<SemaphorePermit<'_>> {
        self.permits.try_acquire().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    const OTHER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

    #[test]
    fn lockout_starts_at_the_threshold_and_backs_off_exponentially() {
        let guard = EnrollmentGuard::default();
        let t0 = Instant::now();
        for _ in 0..MAX_FAILURES - 1 {
            guard.record_failure_at(CLIENT, t0);
        }
        assert_eq!(guard.locked_for_at(CLIENT, t0), None);

        guard.record_failure_at(CLIENT, t0);
        assert_eq!(guard.locked_for_at(CLIENT, t0), Some(BASE_LOCKOUT));
        // the lockout ends by itself
        assert_eq!(guard.locked_for_at(CLIENT, t0 + BASE_LOCKOUT), None);

        let t1 = t0 + BASE_LOCKOUT;
        guard.record_failure_at(CLIENT, t1);
        assert_eq!(guard.locked_for_at(CLIENT, t1), Some(BASE_LOCKOUT * 2));

        // another client is unaffected
        assert_eq!(guard.locked_for_at(OTHER, t0), None);
    }

    #[test]
    fn success_and_quiet_periods_reset_the_counter() {
        let guard = EnrollmentGuard::default();
        let t0 = Instant::now();
        for _ in 0..MAX_FAILURES - 1 {
            guard.record_failure_at(CLIENT, t0);
        }
        guard.record_success(CLIENT);
        guard.record_failure_at(CLIENT, t0);
        assert_eq!(guard.locked_for_at(CLIENT, t0), None);

        for _ in 0..MAX_FAILURES - 2 {
            guard.record_failure_at(CLIENT, t0);
        }
        // a failure after a long quiet period counts as the first one
        guard.record_failure_at(CLIENT, t0 + FAILURE_RESET);
        assert_eq!(guard.locked_for_at(CLIENT, t0 + FAILURE_RESET), None);
    }

    #[test]
    fn lockout_is_capped() {
        let guard = EnrollmentGuard::default();
        let now = Instant::now();
        for _ in 0..MAX_FAILURES + 40 {
            guard.record_failure_at(CLIENT, now);
        }
        assert_eq!(guard.locked_for_at(CLIENT, now), Some(MAX_LOCKOUT));
    }

    #[test]
    fn replayed_message_is_refused_until_the_ttl_expires() {
        let guard = EnrollmentGuard::default();
        let t0 = Instant::now();
        assert!(guard.register_message_at([1; 32], t0));
        assert!(!guard.register_message_at([1; 32], t0 + REPLAY_TTL / 2));
        assert!(guard.register_message_at([2; 32], t0));
        assert!(guard.register_message_at([1; 32], t0 + REPLAY_TTL));
    }

    /// An IPv6 client owns its whole /64: rotating the low bits must not reset the counter, and
    /// a neighbouring /64 is a different client.
    #[test]
    fn ipv6_clients_are_identified_by_their_prefix() {
        let guard = EnrollmentGuard::default();
        let now = Instant::now();
        let in_prefix = |low: u16| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, low));
        for (low, _) in (0_u16..).zip(0..MAX_FAILURES) {
            guard.record_failure_at(in_prefix(low), now);
        }
        assert!(guard.locked_for_at(in_prefix(0xffff), now).is_some());
        let neighbour = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1));
        assert_eq!(guard.locked_for_at(neighbour, now), None);
    }

    /// A full table never pools clients: a new client is tracked on its own (the quietest one
    /// is forgotten), so filling the table with other addresses locks nobody out.
    #[test]
    fn full_table_does_not_lump_clients_together() {
        let guard = EnrollmentGuard::default();
        let t0 = Instant::now();
        for address in (0x0a00_0000_u32..).take(MAX_TRACKED_CLIENTS) {
            guard.record_failure_at(IpAddr::V4(Ipv4Addr::from(address)), t0);
        }
        let newcomer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let bystander = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8));
        let later = t0 + Duration::from_secs(1);
        for _ in 0..MAX_FAILURES {
            guard.record_failure_at(newcomer, later);
        }
        assert!(guard.locked_for_at(newcomer, later).is_some());
        assert_eq!(guard.locked_for_at(bystander, later), None);
        assert!(
            matches!(guard.clients.lock().map(|c| c.len()), Ok(n) if n == MAX_TRACKED_CLIENTS),
            "the table stays bounded"
        );
    }

    /// A full replay cache forgets its oldest message instead of refusing new ones.
    #[test]
    fn full_replay_cache_keeps_accepting_messages() {
        let guard = EnrollmentGuard::default();
        let t0 = Instant::now();
        let fingerprint = |i: u64| {
            let mut f = [0_u8; 32];
            f.iter_mut()
                .zip(i.to_be_bytes())
                .for_each(|(slot, byte)| *slot = byte);
            f
        };
        for i in (0_u64..).take(MAX_REPLAY_ENTRIES) {
            assert!(guard.register_message_at(fingerprint(i), t0 + Duration::from_millis(i)));
        }
        let later = t0 + Duration::from_secs(10);
        assert!(guard.register_message_at(fingerprint(u64::MAX), later));
        assert!(!guard.register_message_at(fingerprint(u64::MAX), later));
        assert!(
            matches!(guard.replays.lock().map(|r| r.len()), Ok(n) if n == MAX_REPLAY_ENTRIES),
            "the cache stays bounded"
        );
        // the oldest entry was the one forgotten
        assert!(guard.register_message_at(fingerprint(0), later));
    }

    #[test]
    fn concurrent_enrollments_are_capped() {
        let guard = EnrollmentGuard::default();
        let permits: Vec<_> = (0..MAX_CONCURRENT_ENROLLMENTS)
            .map(|_| guard.try_begin())
            .collect();
        assert!(permits.iter().all(Option::is_some));
        assert!(guard.try_begin().is_none());
        drop(permits);
        assert!(guard.try_begin().is_some());
    }
}
