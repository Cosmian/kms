use chrono::LocalResult;

use super::AnoError;
use crate::ano_error;

pub enum TimeUnit {
    Second,
    Minute,
    Hour,
    Day,
    Month,
    Year,
}

impl TryFrom<&str> for TimeUnit {
    type Error = AnoError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "Second" => Ok(Self::Second),
            "Minute" => Ok(Self::Minute),
            "Hour" => Ok(Self::Hour),
            "Day" => Ok(Self::Day),
            "Month" => Ok(Self::Month),
            "Year" => Ok(Self::Year),
            _ => Err(ano_error!("Unknown time unit {}", value)),
        }
    }
}

/// Converts a `DateTime` to RFC3339 format.
///
/// # Arguments
///
/// * `date_time` - The `DateTime` value to convert.
/// * `original_date` - The original date value as a string (for error
///   messages).
///
/// # Returns
///
/// * `Ok(String)` - The RFC3339 formatted date and time as a `String` if
///   conversion is successful.
/// * `Err(AnoError)` - An error indicating the reason for conversion failure.
pub fn datetime_to_rfc3339(
    date_time: chrono::LocalResult<chrono::DateTime<chrono::FixedOffset>>,
    original_date: &str,
) -> Result<String, AnoError> {
    match date_time {
        LocalResult::None => Err(ano_error!(
            "Could not apply method on date `{}`.",
            original_date
        )),
        LocalResult::Single(date) => Ok(date.to_rfc3339()),
        LocalResult::Ambiguous(_, _) => Err(ano_error!(
            "Applying method on date `{}` lead to ambiguous result.",
            original_date
        )),
    }
}
