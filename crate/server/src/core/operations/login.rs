//! KMIP 2.1 Login (§6.1.30), Logout (§6.1.31) and Ticket credentials (§2.1.2).
//!
//! Login issues an opaque ticket (32 bytes from the server RNG, Ticket Type `Login`) bound to
//! the user authenticated by the transport (TLS client certificate, JWT, API token or default
//! user). A Request Message whose header carries a `Ticket` credential is processed only when
//! the ticket is known, unexpired and was issued to the same transport user (else the whole
//! message fails with `Invalid Ticket`: an unknown, expired or foreign ticket gives the same
//! answer) and has requests left (else `Usage Limit Exceeded`); each such message consumes one
//! request.
//!
//! Logout invalidates a ticket of the same transport user (else `Invalid Ticket`).
//!
//! A ticket does not replace transport authentication: the HTTP middlewares still authenticate
//! every request, the ticket is an additional check.
//!
//! - Lease Time: an Interval in seconds; 0 or absent selects 1 hour; capped at 24 hours.
//!   The Date Time form of the spec is not modelled (the request fails to decode).
//! - Request Count: the number of Request Messages the ticket authenticates; absent means
//!   unlimited within the lease; zero or negative is `Invalid Field`.
//! - Usage Limits: not implemented, `Feature Not Supported`.
//!
//! Tickets live in server memory only: they are lost on restart and not shared between server
//! instances. The store is bounded globally and per user (`Server Limit Exceeded` beyond), and
//! expired tickets are dropped when the next ticket is issued (they are refused before).

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::{
            kmip_messages::RequestMessageHeader,
            kmip_types::{CredentialValue, ErrorReason, Ticket, TicketType},
        },
        kmip_2_1::kmip_operations::{Login, LoginResponse, Logout, LogoutResponse},
    },
    cosmian_kms_crypto::crypto::KmsRng,
};
use cosmian_logger::info;

use crate::{core::KMS, error::KmsError, result::KResult};

/// Length of a server-generated ticket value.
const TICKET_LENGTH: usize = 32;

/// Resource limits of a [`TicketStore`].
#[derive(Debug, Clone, Copy)]
struct Limits {
    /// Live tickets on the server.
    tickets: usize,
    /// Live tickets of one user.
    tickets_per_user: usize,
    /// Lease of a ticket requested with no (or a zero) Lease Time.
    default_lease: Duration,
    /// Longest lease granted.
    max_lease: Duration,
}

const DEFAULT_LIMITS: Limits = Limits {
    tickets: 10_000,
    tickets_per_user: 64,
    default_lease: Duration::from_secs(3600),
    max_lease: Duration::from_secs(86_400),
};

struct Entry {
    user: String,
    expires: Instant,
    /// Requests left; `None` is unlimited within the lease.
    remaining: Option<u32>,
}

/// In-memory store of the tickets issued by Login, keyed by ticket value.
pub(crate) struct TicketStore {
    tickets: Mutex<HashMap<Vec<u8>, Entry>>,
    limits: Limits,
}

impl Default for TicketStore {
    fn default() -> Self {
        Self::with_limits(DEFAULT_LIMITS)
    }
}

fn invalid_ticket() -> KmsError {
    KmsError::Kmip21Error(
        ErrorReason::Invalid_Ticket,
        "unknown, expired or exhausted ticket".to_owned(),
    )
}

fn invalid_field(message: &str) -> KmsError {
    KmsError::Kmip21Error(ErrorReason::Invalid_Field, format!("Login: {message}"))
}

impl TicketStore {
    fn with_limits(limits: Limits) -> Self {
        Self {
            tickets: Mutex::new(HashMap::new()),
            limits,
        }
    }

    /// Lock the store. Expired tickets may still be present: `redeem` and `revoke` check the
    /// lease themselves, so a request carrying tickets costs O(1) instead of a full scan.
    fn lock(&self) -> MutexGuard<'_, HashMap<Vec<u8>, Entry>> {
        // The map stays consistent if a holder panicked: no update spans a panic point.
        self.tickets.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Issue a ticket to `user`, valid for `lease` (0 = default, capped) and `remaining`
    /// requests (`None` = unlimited).
    fn issue(
        &self,
        rng: &KmsRng,
        user: &str,
        lease: Duration,
        remaining: Option<u32>,
    ) -> KResult<Vec<u8>> {
        let lease = if lease.is_zero() {
            self.limits.default_lease
        } else {
            lease.min(self.limits.max_lease)
        };
        let mut value = vec![0_u8; TICKET_LENGTH];
        rng.fill_bytes(&mut value)?;
        // One critical section for the limit check and the insertion.
        let mut tickets = self.lock();
        let now = Instant::now();
        tickets.retain(|_, entry| entry.expires > now);
        let per_user = tickets.values().filter(|e| e.user == user).count();
        if tickets.len() >= self.limits.tickets || per_user >= self.limits.tickets_per_user {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Server_Limit_Exceeded,
                "Login: too many live tickets; let some expire first".to_owned(),
            ));
        }
        tickets.insert(
            value.clone(),
            Entry {
                user: user.to_owned(),
                expires: Instant::now() + lease,
                remaining,
            },
        );
        Ok(value)
    }

    /// Consume one request of `ticket` for `user`. An exhausted ticket stays known until its
    /// lease ends, and is refused with `Usage Limit Exceeded` (as the OASIS draft test case
    /// TC-LOGIN-3-20 expects).
    fn redeem(&self, ticket: &Ticket, user: &str) -> KResult<()> {
        if ticket.ticket_type != TicketType::Login || ticket.ticket_value.len() != TICKET_LENGTH {
            return Err(invalid_ticket());
        }
        let mut tickets = self.lock();
        let now = Instant::now();
        let entry = tickets
            .get_mut(&ticket.ticket_value)
            .filter(|entry| entry.user == user && entry.expires > now)
            .ok_or_else(invalid_ticket)?;
        match &mut entry.remaining {
            Some(0) => Err(KmsError::Kmip21Error(
                ErrorReason::Usage_Limit_Exceeded,
                "the ticket's Request Count is exhausted".to_owned(),
            )),
            Some(n) => {
                *n -= 1;
                Ok(())
            }
            None => Ok(()),
        }
    }

    /// Invalidate `ticket`, issued to `user`, whatever requests it has left.
    fn revoke(&self, ticket: &Ticket, user: &str) -> KResult<()> {
        let mut tickets = self.lock();
        let own_login_ticket = ticket.ticket_type == TicketType::Login
            && tickets
                .get(&ticket.ticket_value)
                .is_some_and(|entry| entry.user == user && entry.expires > Instant::now());
        if !own_login_ticket {
            return Err(invalid_ticket());
        }
        tickets.remove(&ticket.ticket_value);
        Ok(())
    }
}

/// Executes the Login operation: issues a ticket bound to `user`.
pub(crate) fn login(kms: &KMS, request: &Login, user: &str) -> KResult<LoginResponse> {
    if request.usage_limits.is_some() {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Feature_Not_Supported,
            "Login: Usage Limits are not supported".to_owned(),
        ));
    }
    let remaining = match request.request_count {
        None => None,
        Some(n) if n > 0 => Some(n.unsigned_abs()),
        Some(_) => return Err(invalid_field("the Request Count must be positive")),
    };
    let lease = Duration::from_secs(request.lease_time.map_or(0, |l| u64::from(l.as_secs())));
    let ticket_value = kms.tickets.issue(&kms.rng, user, lease, remaining)?;
    info!("KMIP Login: ticket issued to user {user:?}");
    Ok(LoginResponse {
        ticket: Ticket {
            ticket_type: TicketType::Login,
            ticket_value,
        },
    })
}

/// Executes the Logout operation: invalidates a ticket issued to `user`.
pub(crate) fn logout(kms: &KMS, request: &Logout, user: &str) -> KResult<LogoutResponse> {
    kms.tickets.revoke(&request.ticket, user)?;
    info!("KMIP Logout: ticket of user {user:?} invalidated");
    Ok(LogoutResponse)
}

/// Validates and consumes the `Ticket` credentials of a request header for `user`
/// (`Invalid Ticket` on failure). Other credential types are left to their own checks.
pub(crate) fn redeem_ticket_credentials(
    kms: &KMS,
    header: &RequestMessageHeader,
    user: &str,
) -> KResult<()> {
    let Some(authentication) = &header.authentication else {
        return Ok(());
    };
    for credential in &authentication.credential {
        if let CredentialValue::Ticket { ticket } = &credential.credential_value {
            kms.tickets.redeem(ticket, user)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test setup")]
mod tests {
    use super::*;

    fn reason(result: KResult<impl Sized>) -> Option<ErrorReason> {
        match result.err()? {
            KmsError::Kmip21Error(r, _) => Some(r),
            _ => None,
        }
    }

    fn ticket(value: Vec<u8>) -> Ticket {
        Ticket {
            ticket_type: TicketType::Login,
            ticket_value: value,
        }
    }

    #[test]
    fn request_count_is_consumed_then_exhausted() {
        let store = TicketStore::default();
        let rng = KmsRng::new();
        let t = ticket(store.issue(&rng, "alice", Duration::ZERO, Some(2)).unwrap());
        assert_eq!(t.ticket_value.len(), TICKET_LENGTH);
        store.redeem(&t, "alice").unwrap();
        store.redeem(&t, "alice").unwrap();
        assert_eq!(
            reason(store.redeem(&t, "alice")),
            Some(ErrorReason::Usage_Limit_Exceeded)
        );
        // Another user learns nothing about the ticket.
        assert_eq!(
            reason(store.redeem(&t, "bob")),
            Some(ErrorReason::Invalid_Ticket)
        );
    }

    #[test]
    fn logout_invalidates_only_own_ticket() {
        let store = TicketStore::default();
        let rng = KmsRng::new();
        let t = ticket(store.issue(&rng, "alice", Duration::ZERO, Some(1)).unwrap());
        assert_eq!(
            reason(store.revoke(&t, "bob")),
            Some(ErrorReason::Invalid_Ticket)
        );
        store.redeem(&t, "alice").unwrap();
        // An exhausted ticket can still be logged out, once.
        store.revoke(&t, "alice").unwrap();
        assert_eq!(
            reason(store.redeem(&t, "alice")),
            Some(ErrorReason::Invalid_Ticket)
        );
        assert_eq!(
            reason(store.revoke(&t, "alice")),
            Some(ErrorReason::Invalid_Ticket)
        );
    }

    #[test]
    fn unlimited_ticket_and_other_user_rejected() {
        let store = TicketStore::default();
        let rng = KmsRng::new();
        let t = ticket(store.issue(&rng, "alice", Duration::ZERO, None).unwrap());
        for _ in 0..5 {
            store.redeem(&t, "alice").unwrap();
        }
        assert_eq!(
            reason(store.redeem(&t, "bob")),
            Some(ErrorReason::Invalid_Ticket)
        );
        // Unknown value and wrong length are rejected alike.
        assert_eq!(
            reason(store.redeem(&ticket(vec![0; TICKET_LENGTH]), "alice")),
            Some(ErrorReason::Invalid_Ticket)
        );
        assert_eq!(
            reason(store.redeem(&ticket(vec![0; 3]), "alice")),
            Some(ErrorReason::Invalid_Ticket)
        );
    }

    /// Marks the ticket as expired now, without sleeping.
    fn expire(store: &TicketStore, t: &Ticket) {
        store.lock().get_mut(&t.ticket_value).unwrap().expires = Instant::now();
    }

    #[test]
    fn expired_ticket_is_refused_even_with_requests_left() {
        let store = TicketStore::default();
        let rng = KmsRng::new();
        let limited = ticket(store.issue(&rng, "alice", Duration::ZERO, Some(5)).unwrap());
        let unlimited = ticket(store.issue(&rng, "alice", Duration::ZERO, None).unwrap());
        for t in [&limited, &unlimited] {
            store.redeem(t, "alice").unwrap();
            expire(&store, t);
            // Same answer as an unknown ticket, not `Usage Limit Exceeded`.
            assert_eq!(
                reason(store.redeem(t, "alice")),
                Some(ErrorReason::Invalid_Ticket)
            );
            // An expired ticket cannot be logged out either.
            assert_eq!(
                reason(store.revoke(t, "alice")),
                Some(ErrorReason::Invalid_Ticket)
            );
        }
    }

    #[test]
    fn exhausted_ticket_becomes_invalid_when_its_lease_ends() {
        let store = TicketStore::default();
        let rng = KmsRng::new();
        let t = ticket(store.issue(&rng, "alice", Duration::ZERO, Some(1)).unwrap());
        store.redeem(&t, "alice").unwrap();
        assert_eq!(
            reason(store.redeem(&t, "alice")),
            Some(ErrorReason::Usage_Limit_Exceeded)
        );
        expire(&store, &t);
        assert_eq!(
            reason(store.redeem(&t, "alice")),
            Some(ErrorReason::Invalid_Ticket)
        );
    }

    #[test]
    fn expired_tickets_free_the_quota_and_stay_invalid() {
        let store = TicketStore::with_limits(Limits {
            tickets: 1,
            tickets_per_user: 1,
            ..DEFAULT_LIMITS
        });
        let rng = KmsRng::new();
        let old = ticket(store.issue(&rng, "alice", Duration::ZERO, None).unwrap());
        assert_eq!(
            reason(store.issue(&rng, "bob", Duration::ZERO, None)),
            Some(ErrorReason::Server_Limit_Exceeded)
        );
        expire(&store, &old);
        // The expired ticket counts neither globally nor for its user.
        let fresh = ticket(store.issue(&rng, "alice", Duration::ZERO, None).unwrap());
        assert_eq!(
            reason(store.redeem(&old, "alice")),
            Some(ErrorReason::Invalid_Ticket)
        );
        store.redeem(&fresh, "alice").unwrap();
    }

    #[test]
    fn lease_defaults_and_is_capped() {
        let store = TicketStore::with_limits(Limits {
            default_lease: Duration::from_secs(10),
            max_lease: Duration::from_secs(100),
            ..DEFAULT_LIMITS
        });
        let rng = KmsRng::new();
        // `expires` lies in [before + lease, after + lease].
        let expires_after = |lease: Duration| {
            let before = Instant::now();
            let t = ticket(store.issue(&rng, "alice", lease, None).unwrap());
            let after = Instant::now();
            let expires = store.lock().get(&t.ticket_value).unwrap().expires;
            (before, expires, after)
        };
        for (requested, granted) in [
            (Duration::ZERO, Duration::from_secs(10)),
            (Duration::from_secs(50), Duration::from_secs(50)),
            (Duration::from_secs(1_000_000), Duration::from_secs(100)),
        ] {
            let (before, expires, after) = expires_after(requested);
            assert!(expires >= before + granted && expires <= after + granted);
        }
    }

    #[test]
    fn store_is_bounded() {
        let store = TicketStore::with_limits(Limits {
            tickets: 3,
            tickets_per_user: 2,
            ..DEFAULT_LIMITS
        });
        let rng = KmsRng::new();
        store.issue(&rng, "alice", Duration::ZERO, None).unwrap();
        store.issue(&rng, "alice", Duration::ZERO, None).unwrap();
        assert_eq!(
            reason(store.issue(&rng, "alice", Duration::ZERO, None)),
            Some(ErrorReason::Server_Limit_Exceeded)
        );
        store.issue(&rng, "bob", Duration::ZERO, None).unwrap();
        assert_eq!(
            reason(store.issue(&rng, "carol", Duration::ZERO, None)),
            Some(ErrorReason::Server_Limit_Exceeded)
        );
    }
}
