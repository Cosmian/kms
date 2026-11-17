use std::str::FromStr;

use time::{OffsetDateTime, error::ComponentRange, format_description::well_known::Rfc3339};

use super::AnoError;

pub enum TimeUnit {
    Second,
    Minute,
    Hour,
    Day,
    Month,
    Year,
}

impl FromStr for TimeUnit {
    type Err = AnoError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "Second" => Ok(Self::Second),
            "Minute" => Ok(Self::Minute),
            "Hour" => Ok(Self::Hour),
            "Day" => Ok(Self::Day),
            "Month" => Ok(Self::Month),
            "Year" => Ok(Self::Year),
            _ => Err(AnoError::AnonymizationError(format!(
                "Unknown time unit {value}"
            ))),
        }
    }
}

/// Parses an RFC3339 date string.
///
/// # Arguments
///
/// * `date_str` - The date string to parse.
///
/// # Returns
///
/// The parsed `OffsetDateTime` (keeping the original UTC offset), or an `AnoError` if the
/// string is not a valid RFC3339 date.
pub(super) fn parse_rfc3339(date_str: &str) -> Result<OffsetDateTime, AnoError> {
    OffsetDateTime::parse(date_str, &Rfc3339).map_err(|e| {
        AnoError::AnonymizationError(format!(
            "invalid RFC3339 date '{date_str}': {e} (expected format: 2023-04-07T12:34:56+02:00)"
        ))
    })
}

/// Converts an `OffsetDateTime` to RFC3339 format.
///
/// The offset is always printed numerically (`+00:00` for UTC, never `Z`) and sub-seconds
/// are not printed.
///
/// # Arguments
///
/// * `date_time` - The date computation result to convert.
/// * `original_date` - The original date value as a string (for error
///   messages).
///
/// # Returns
///
/// * `Ok(String)` - The RFC3339 formatted date and time as a `String` if
///   conversion is successful.
/// * `Err(AnoError)` - An error indicating the reason for conversion failure.
pub fn datetime_to_rfc3339(
    date_time: Result<OffsetDateTime, ComponentRange>,
    original_date: &str,
) -> Result<String, AnoError> {
    let date = date_time.map_err(|e| {
        AnoError::AnonymizationError(format!(
            "Could not apply method on date `{original_date}`: {e}."
        ))
    })?;
    date.format(time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second][offset_hour sign:mandatory]:[offset_minute]"
    ))
    .map_err(|e| {
        AnoError::AnonymizationError(format!(
            "Could not format date resulting from `{original_date}`: {e}"
        ))
    })
}
