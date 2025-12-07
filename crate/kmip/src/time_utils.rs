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
}
