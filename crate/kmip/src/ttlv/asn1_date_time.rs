//! ASN.1 time conversion for KMIP's `Validity Date` field.

use serde::{Deserialize, Deserializer, Serializer, ser::Error as _};
use time::{
    OffsetDateTime, PrimitiveDateTime, UtcOffset,
    format_description::{FormatItem, well_known::Rfc3339},
    macros::format_description,
};

use super::date_time;

const GENERALIZED_TIME: &[FormatItem<'static>] =
    format_description!("[year][month][day][hour][minute][second]Z");

/// Parse ASN.1 `GeneralizedTime` or `UTCTime` as UTC.
pub(crate) fn parse(s: &str) -> Result<OffsetDateTime, time::error::Parse> {
    if s.len() == 13 {
        let century = if s
            .as_bytes()
            .first()
            .is_some_and(|year_tens| *year_tens >= b'5')
        {
            "19"
        } else {
            "20"
        };
        let time = format!("{century}{s}");
        let parsed = PrimitiveDateTime::parse(&time, GENERALIZED_TIME);
        return parsed.map(PrimitiveDateTime::assume_utc);
    }
    PrimitiveDateTime::parse(s, GENERALIZED_TIME)
        .map(PrimitiveDateTime::assume_utc)
        .or_else(|_| OffsetDateTime::parse(s, &Rfc3339))
}

/// Format an instant as ASN.1 `GeneralizedTime` in UTC.
pub(crate) fn format(time: OffsetDateTime) -> String {
    let time = time.to_offset(UtcOffset::UTC);
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second()
    )
}

pub(crate) fn serialize<S: Serializer>(
    value: &Option<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let value = match value {
        // Whole seconds only: `date_time` emits a DateTime node just for those, and
        // ASN.1 GeneralizedTime as formatted here has no fraction anyway.
        Some(value) => Some(
            parse(value)
                .map_err(|e| S::Error::custom(format!("invalid Validity Date '{value}': {e}")))?
                .replace_nanosecond(0)
                .map_err(S::Error::custom)?,
        ),
        None => None,
    };
    date_time::serialize_option(&value, serializer)
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    // A Date-Time node reads as an RFC 3339 string; earlier clients sent a TextString (already
    // ASN.1 GeneralizedTime), which is kept as is.
    Ok(Option::<String>::deserialize(deserializer)?
        .map(|value| OffsetDateTime::parse(&value, &Rfc3339).map_or(value, format)))
}

#[cfg(test)]
mod tests {
    use super::parse;
    use crate::{
        KmipError,
        kmip_2_1::kmip_operations::Validate,
        ttlv::{TTLValue, from_ttlv, to_ttlv},
    };

    #[test]
    fn validity_date_round_trips_as_datetime() -> Result<(), KmipError> {
        let ttlv = to_ttlv(&Validate {
            certificate: None,
            unique_identifier: None,
            validity_time: Some("20500101000000Z".to_owned()),
        })?;
        let validity_date = match &ttlv.value {
            TTLValue::Structure(fields) => fields.iter().find(|field| field.tag == "ValidityDate"),
            _ => None,
        };
        if !matches!(
            validity_date.map(|field| &field.value),
            Some(TTLValue::DateTime(_))
        ) {
            return Err(KmipError::Default(
                "Validity Date was not serialized as DateTime".to_owned(),
            ));
        }
        let decoded: Validate = from_ttlv(ttlv)?;
        if decoded.validity_time.as_deref() == Some("20500101000000Z") {
            Ok(())
        } else {
            Err(KmipError::Default(format!(
                "Validity Date round trip mismatch: {:?}",
                decoded.validity_time
            )))
        }
    }

    #[test]
    fn utc_time_uses_rfc_5280_century_rule() -> Result<(), String> {
        let date = parse("500101000000Z").map_err(|error| error.to_string())?;
        if date.year() == 1950 {
            Ok(())
        } else {
            Err(format!("expected year 1950, got {}", date.year()))
        }
    }

    #[test]
    fn iso_8601_validity_date_is_normalised_to_generalized_time() -> Result<(), KmipError> {
        // The UI (`toISOString()`) and the CLI send RFC 3339 / ISO-8601 values.
        let ttlv = to_ttlv(&Validate {
            certificate: None,
            unique_identifier: None,
            validity_time: Some("2026-10-19T09:00:00.250Z".to_owned()),
        })?;
        let decoded: Validate = from_ttlv(ttlv)?;
        if decoded.validity_time.as_deref() == Some("20261019090000Z") {
            Ok(())
        } else {
            Err(KmipError::Default(format!(
                "ISO-8601 Validity Date was not normalised: {:?}",
                decoded.validity_time
            )))
        }
    }

    #[test]
    fn parses_rfc3339_validity_date() -> Result<(), String> {
        let date = parse("2026-10-19T09:00:00.000Z").map_err(|error| error.to_string())?;
        if date.year() == 2026 && date.month() == time::Month::October && date.day() == 19 {
            Ok(())
        } else {
            Err(format!("unexpected parsed date: {date}"))
        }
    }
}
