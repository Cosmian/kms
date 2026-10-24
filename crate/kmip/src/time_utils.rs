use time::OffsetDateTime;

use crate::error::KmipError;

/// Returns the current UTC time with milliseconds set to zero.
///
/// This function is used to normalize timestamps across the KMIP implementation,
/// ensuring consistent time representations without millisecond precision.
///
/// # Returns
///
/// Returns the current `OffsetDateTime` with milliseconds set to 0.
///
/// # Errors
///
/// Returns a `KmipError::Default` if the millisecond replacement fails.
#[cfg(not(target_arch = "wasm32"))]
pub fn time_normalize() -> Result<OffsetDateTime, KmipError> {
    OffsetDateTime::now_utc()
        .replace_millisecond(0)
        .map_err(|e| KmipError::Default(e.to_string()))
}

#[cfg(target_arch = "wasm32")]
pub fn time_normalize() -> Result<OffsetDateTime, KmipError> {
    // In WASM, rely on JS Date.now to avoid potential panics from time::now_utc
    let ms = js_sys::Date::now();
    let secs = (ms / 1000.0).floor() as i64;
    let ts =
        OffsetDateTime::from_unix_timestamp(secs).map_err(|e| KmipError::Default(e.to_string()))?;
    ts.replace_millisecond(0)
        .map_err(|e| KmipError::Default(e.to_string()))
}

/// Creation instant of a new managed object, its Initial Date: the current UTC time with
/// sub-second precision, strictly increasing within the process, so that objects created
/// within one second keep their creation order (Locate, KMIP 2.1 §6.1.28). The KMIP
/// encodings of a Date-Time carry whole seconds.
///
/// # Errors
///
/// Returns a `KmipError::Default` if the clock lock is poisoned or the time is out of range.
#[cfg(not(target_arch = "wasm32"))]
pub fn creation_time() -> Result<OffsetDateTime, KmipError> {
    static LAST: std::sync::Mutex<i128> = std::sync::Mutex::new(0);
    let now = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let mut last = LAST.lock().map_err(|e| KmipError::Default(e.to_string()))?;
    *last = now.max(last.saturating_add(1));
    OffsetDateTime::from_unix_timestamp_nanos(*last).map_err(|e| KmipError::Default(e.to_string()))
}

/// See the non-WASM `creation_time`; WASM clients do not create managed objects.
#[cfg(target_arch = "wasm32")]
pub fn creation_time() -> Result<OffsetDateTime, KmipError> {
    time_normalize()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_time_normalize() {
        let normalized_time = time_normalize().expect("time_normalize should succeed");

        // Verify that milliseconds are set to 0
        assert_eq!(
            normalized_time.millisecond(),
            0,
            "Milliseconds should be set to 0"
        );

        // Verify that the time is recent (within the last second)
        let now = OffsetDateTime::now_utc();
        let diff = (now - normalized_time).whole_seconds().abs();
        assert!(
            diff <= 1,
            "Normalized time should be within 1 second of current time"
        );
    }

    /// Same-second creations stay ordered, in memory and in the stored JSON text the SQL
    /// stores sort on, while the KMIP JSON and binary encodings carry whole seconds.
    #[test]
    fn test_creation_time_orders_same_second_creations() {
        use crate::ttlv::{KmipFlavor, TTLV, TTLValue};

        let first = creation_time().expect("creation_time");
        let mut earlier = first;
        for _ in 0..4 {
            let later = creation_time().expect("creation_time");
            assert!(earlier < later);
            let text = |t: OffsetDateTime| serde_json::to_string(&t).expect("serde");
            assert!(
                text(earlier) < text(later),
                "{} {}",
                text(earlier),
                text(later)
            );
            earlier = later;
        }
        let ttlv = TTLV {
            tag: "InitialDate".into(),
            value: TTLValue::DateTime(first),
        };
        let json = serde_json::to_string(&ttlv).expect("json");
        assert!(!json.contains('.'), "{json}");
        let bytes = ttlv.to_bytes(KmipFlavor::Kmip2).expect("bytes");
        let decoded = TTLV::from_bytes(&bytes, KmipFlavor::Kmip2).expect("decode");
        let whole_seconds = first.replace_nanosecond(0).expect("truncate");
        assert!(
            matches!(decoded.value, TTLValue::DateTime(d) if d == whole_seconds),
            "{decoded:?}"
        );
    }
}
