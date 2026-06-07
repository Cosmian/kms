use std::fmt::{self, Display, Formatter};

use cosmian_kmip::{
    KmipError,
    kmip_0::kmip_types::{CryptographicUsageMask, ErrorReason, State},
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::Object,
        kmip_types::{CryptographicAlgorithm, UsageLimitsUnit},
    },
    time_normalize,
};

use crate::UserId;

/// An object with its metadata such as owner, permissions and state
///
/// This is the main representation of objects through the KMS server.
/// Mpe APIs should use this representation.
#[derive(Clone)]
pub struct ObjectWithMetadata {
    id: String,
    // this is the object as registered in the DN. For a key, it may be wrapped or unwrapped
    object: Object,
    owner: UserId,
    state: State,
    attributes: Attributes,
    /// The domain this object belongs to (for OPA domain-scoped RBAC).
    /// Stamped at creation from the creator's `user_domain`; empty string for legacy objects.
    domain: String,
}

impl ObjectWithMetadata {
    #[must_use]
    pub fn new(
        id: String,
        object: Object,
        owner: impl Into<UserId>,
        state: State,
        attributes: Attributes,
        domain: String,
    ) -> Self {
        Self {
            id,
            object,
            owner: owner.into(),
            state,
            attributes,
            domain,
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn object(&self) -> &Object {
        &self.object
    }

    /// Set a new object, clearing the cached unwrapped version
    /// if any
    pub fn set_object(&mut self, object: Object) {
        self.object = object;
    }

    /// Return a mutable borrow to the Object
    /// Do not use this to set a new object or make sure you clear
    /// the cached unwrapped object
    pub const fn object_mut(&mut self) -> &mut Object {
        &mut self.object
    }

    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Return the owner as a typed [`UserId`].
    #[must_use]
    pub const fn owner_id(&self) -> &UserId {
        &self.owner
    }

    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    #[must_use]
    pub const fn attributes(&self) -> &Attributes {
        &self.attributes
    }

    pub const fn attributes_mut(&mut self) -> &mut Attributes {
        &mut self.attributes
    }

    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Resolve the effective cryptographic algorithm for this managed object.
    ///
    /// Checks the key block's algorithm first, then falls back to the object's
    /// external attributes. Returns `None` when neither source provides a value.
    #[must_use]
    pub fn resolve_key_algorithm(&self) -> Option<CryptographicAlgorithm> {
        self.object
            .key_block()
            .ok()
            .and_then(|kb| kb.cryptographic_algorithm().copied())
            .or(self.attributes.cryptographic_algorithm)
    }

    // ─── Lifecycle predicates ────────────────────────────────────────────────

    /// Determine the effective KMIP state based on stored state and time-based
    /// transitions (activation / deactivation).
    ///
    /// - `PreActive` → `Active` when `activation_date` ≤ now.
    /// - `Active` → `Deactivated` when `deactivation_date` ≤ now.
    ///
    /// Falls back to the stored state if the system clock cannot be read.
    #[must_use]
    pub fn effective_state(&self) -> State {
        let Ok(now) = time_normalize() else {
            return self.state;
        };
        match self.state {
            State::PreActive => {
                let activation_date = self.attributes.activation_date.or_else(|| {
                    self.object
                        .attributes()
                        .ok()
                        .and_then(|attrs| attrs.activation_date)
                });
                if activation_date.is_some_and(|d| d <= now) {
                    State::Active
                } else {
                    State::PreActive
                }
            }
            State::Active => {
                let deactivation_date = self.attributes.deactivation_date.or_else(|| {
                    self.object
                        .attributes()
                        .ok()
                        .and_then(|attrs| attrs.deactivation_date)
                });
                if deactivation_date.is_some_and(|d| d <= now) {
                    State::Deactivated
                } else {
                    State::Active
                }
            }
            other => other,
        }
    }

    /// Check whether the current time falls within the KMIP process window
    /// (`ProcessStartDate`..`ProtectStopDate`).
    ///
    /// Returns `true` when usage is allowed (window is open or no window is set).
    /// Returns `false` when the key is outside its process window.
    /// Falls back to `true` if the system clock cannot be read.
    ///
    /// # Attribute precedence
    ///
    /// The external (database) attributes stored in `self.attributes` are checked
    /// first, with the embedded key-block attributes as fallback.  This mirrors
    /// `effective_state()` and ensures that `SetAttribute ProcessStartDate / ProtectStopDate`
    /// calls are honoured even when the key block itself was not modified.
    #[must_use]
    pub fn is_within_process_window(&self) -> bool {
        if self.effective_state() != State::Active {
            return true; // window only applies to Active keys
        }
        let Ok(now) = time_normalize() else {
            return true;
        };
        // Prefer external (database) attributes; fall back to embedded key-block attributes.
        let kb_attrs = self.object.attributes().ok();
        let process_start = self
            .attributes
            .process_start_date
            .or_else(|| kb_attrs.as_ref().and_then(|a| a.process_start_date));
        let protect_stop = self
            .attributes
            .protect_stop_date
            .or_else(|| kb_attrs.as_ref().and_then(|a| a.protect_stop_date));
        let too_early = process_start.is_some_and(|d| now < d);
        let too_late = protect_stop.is_some_and(|d| now > d);
        !(too_early || too_late)
    }

    // ─── Usage predicates ────────────────────────────────────────────────────

    /// Check whether the object's usage mask permits the given operation.
    ///
    /// In **lenient** mode a missing mask (`None`) is treated as "allowed",
    /// which supports legacy Certificates/Public Keys imported without masks.
    #[must_use]
    pub fn has_usage_mask(&self, required: CryptographicUsageMask, lenient: bool) -> bool {
        let attributes = self
            .object
            .attributes()
            .unwrap_or_else(|_| self.attributes());
        if lenient && attributes.cryptographic_usage_mask.is_none() {
            return true;
        }
        attributes
            .is_usage_authorized_for(required)
            .unwrap_or(false)
    }

    /// Check whether the key's remaining usage budget is sufficient for
    /// `data_len` bytes of payload.
    ///
    /// Returns `true` when no `UsageLimits` are set or the budget is sufficient.
    #[must_use]
    pub fn has_usage_budget(&self, data_len: usize) -> bool {
        let Some(ul) = self.attributes.usage_limits.as_ref() else {
            return true;
        };
        match ul.usage_limits_unit {
            UsageLimitsUnit::Byte => {
                let needed = i64::try_from(data_len).unwrap_or(i64::MAX);
                ul.usage_limits_total >= needed
            }
            UsageLimitsUnit::Object | UsageLimitsUnit::Block | UsageLimitsUnit::Operation => {
                ul.usage_limits_total > 0
            }
        }
    }

    // ─── Enforcement (error-returning) ───────────────────────────────────────

    /// Enforce the KMIP process-window constraints.
    ///
    /// An Active key whose current time is before `ProcessStartDate` or after
    /// `ProtectStopDate` is rejected with `Wrong_Key_Lifecycle_State`.
    pub fn check_process_window(&self) -> Result<(), KmipError> {
        if !self.is_within_process_window() {
            return Err(KmipError::Kmip21(
                ErrorReason::Wrong_Key_Lifecycle_State,
                "DENIED".to_owned(),
            ));
        }
        Ok(())
    }

    /// Enforce `UsageLimits` before a cryptographic operation.
    ///
    /// Returns `Err(Permission_Denied)` when the key's remaining usage budget
    /// is insufficient for the requested `data_len` bytes.
    pub fn enforce_usage_limits(&self, data_len: usize) -> Result<(), KmipError> {
        if !self.has_usage_budget(data_len) {
            return Err(KmipError::Kmip21(
                ErrorReason::Permission_Denied,
                "DENIED".to_owned(),
            ));
        }
        Ok(())
    }
}

impl Display for ObjectWithMetadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ObjectWithMetadata {{ id: {}, object: {}, owner: {}, state: {}, attributes: {}, domain: {} }}",
            self.id, self.object, self.owner, self.state, self.attributes, self.domain
        )
    }
}

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)]
mod tests {
    use cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
            kmip_objects::{Object, SymmetricKey},
            kmip_types::{CryptographicAlgorithm, KeyFormatType},
        },
        time_normalize,
    };
    use time::Duration;
    use zeroize::Zeroizing;

    use super::ObjectWithMetadata;

    /// Build a minimal `Object::SymmetricKey` with empty embedded attributes.
    fn test_object() -> Object {
        Object::SymmetricKey(SymmetricKey {
            key_block: KeyBlock {
                key_format_type: KeyFormatType::Raw,
                key_value: Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(Zeroizing::new(vec![0_u8; 32])),
                    attributes: Some(Attributes::default()),
                }),
                key_compression_type: None,
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                cryptographic_length: Some(256),
                key_wrapping_data: None,
            },
        })
    }

    fn active_owm(ext_attrs: Attributes) -> ObjectWithMetadata {
        ObjectWithMetadata::new(
            "test-key".to_owned(),
            test_object(),
            "owner".to_owned(),
            State::Active,
            ext_attrs,
            String::new(),
        )
    }

    // ── is_within_process_window ──────────────────────────────────────────────

    #[test]
    fn test_process_window_no_dates_is_open() {
        let owm = active_owm(Attributes::default());
        assert!(owm.is_within_process_window());
    }

    /// `ProtectStopDate` set via `SetAttribute` (external DB attrs) in the past
    /// must be honoured.  This verifies the bug-fix: the old code only checked the
    /// key-block embedded attributes and would have returned `true` here.
    #[test]
    fn test_process_window_protect_stop_past_in_external_attrs_is_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = time_normalize()?;
        let owm = active_owm(Attributes {
            protect_stop_date: Some(now - Duration::hours(1)),
            ..Default::default()
        });
        assert!(!owm.is_within_process_window());
        Ok(())
    }

    #[test]
    fn test_process_window_protect_stop_future_is_open() -> Result<(), Box<dyn std::error::Error>> {
        let now = time_normalize()?;
        let owm = active_owm(Attributes {
            protect_stop_date: Some(now + Duration::hours(1)),
            ..Default::default()
        });
        assert!(owm.is_within_process_window());
        Ok(())
    }

    /// `ProcessStartDate` set via `SetAttribute` (external DB attrs) in the future
    /// must be honoured.  Same fix as the `ProtectStopDate` case above.
    #[test]
    fn test_process_window_process_start_future_in_external_attrs_is_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = time_normalize()?;
        let owm = active_owm(Attributes {
            process_start_date: Some(now + Duration::hours(1)),
            ..Default::default()
        });
        assert!(!owm.is_within_process_window());
        Ok(())
    }

    #[test]
    fn test_process_window_process_start_past_is_open() -> Result<(), Box<dyn std::error::Error>> {
        let now = time_normalize()?;
        let owm = active_owm(Attributes {
            process_start_date: Some(now - Duration::hours(1)),
            ..Default::default()
        });
        assert!(owm.is_within_process_window());
        Ok(())
    }

    #[test]
    fn test_process_window_both_dates_valid_is_open() -> Result<(), Box<dyn std::error::Error>> {
        let now = time_normalize()?;
        let owm = active_owm(Attributes {
            process_start_date: Some(now - Duration::hours(1)),
            protect_stop_date: Some(now + Duration::hours(1)),
            ..Default::default()
        });
        assert!(owm.is_within_process_window());
        Ok(())
    }

    /// `ProtectStopDate` embedded inside the key block (not via `SetAttribute`)
    /// must still be honoured — the fallback path remains correct.
    #[test]
    fn test_process_window_protect_stop_past_in_key_block_is_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = time_normalize()?;
        // Build an object with ProtectStopDate inside the key block's embedded attrs.
        let kb_attrs = Attributes {
            protect_stop_date: Some(now - Duration::hours(1)),
            ..Default::default()
        };
        let object = Object::SymmetricKey(SymmetricKey {
            key_block: KeyBlock {
                key_format_type: KeyFormatType::Raw,
                key_value: Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(Zeroizing::new(vec![0_u8; 32])),
                    attributes: Some(kb_attrs),
                }),
                key_compression_type: None,
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                cryptographic_length: Some(256),
                key_wrapping_data: None,
            },
        });
        let owm = ObjectWithMetadata::new(
            "test-key".to_owned(),
            object,
            "owner".to_owned(),
            State::Active,
            Attributes::default(), // no external attrs
            String::new(),
        );
        assert!(!owm.is_within_process_window());
        Ok(())
    }

    /// Non-Active keys bypass the process-window check (always open).
    #[test]
    fn test_process_window_non_active_state_always_open() -> Result<(), Box<dyn std::error::Error>>
    {
        let now = time_normalize()?;
        for state in [
            State::Compromised,
            State::Deactivated,
            State::Destroyed,
            State::PreActive,
        ] {
            let owm = ObjectWithMetadata::new(
                "test-key".to_owned(),
                test_object(),
                "owner".to_owned(),
                state,
                Attributes {
                    protect_stop_date: Some(now - Duration::hours(1)),
                    ..Default::default()
                },
                String::new(),
            );
            assert!(
                owm.is_within_process_window(),
                "expected window open for state {state:?}"
            );
        }
        Ok(())
    }
}
