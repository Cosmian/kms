//! Direct TTLV `DateTime` serialization for message-header time stamps.
//!
//! Serde's `OffsetDateTime` encoding in non-human-readable formats is a
//! 9-integer tuple, which the TTLV serializer emits as nine `Integer` nodes that
//! `normalize_ttlv` later folds back into one `DateTime`. Header time stamps sit
//! on every request and response, so they instead go through
//! `serialize_newtype_struct` under the reserved name [`DATETIME_NEWTYPE`] with
//! the unix timestamp as payload, and the TTLV serializer emits the `DateTime`
//! node directly. Reading needs no counterpart: the deserializer already maps a
//! `DateTime` node onto `OffsetDateTime`.

use serde::{Serialize, Serializer};
use time::OffsetDateTime;

/// Reserved newtype-struct name the TTLV serializer recognises to emit a
/// `DateTime` primitive from a unix timestamp in seconds.
pub(crate) const DATETIME_NEWTYPE: &str = "$KmipDateTime";

struct DateTimeRef<'a>(&'a OffsetDateTime);

impl Serialize for DateTimeRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // The marker only carries whole UTC seconds; any other value, and any
        // human-readable format, keeps serde's own `OffsetDateTime` encoding.
        if !serializer.is_human_readable() && self.0.nanosecond() == 0 && self.0.offset().is_utc() {
            serializer.serialize_newtype_struct(DATETIME_NEWTYPE, &self.0.unix_timestamp())
        } else {
            self.0.serialize(serializer)
        }
    }
}

/// `serialize_with` helper for an `OffsetDateTime` field.
pub(crate) fn serialize<S: Serializer>(
    value: &OffsetDateTime,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    DateTimeRef(value).serialize(serializer)
}

/// `serialize_with` helper for an `Option<OffsetDateTime>` field.
#[expect(
    clippy::ref_option,
    reason = "signature imposed by serde's serialize_with"
)]
pub(crate) fn serialize_option<S: Serializer>(
    value: &Option<OffsetDateTime>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    value.as_ref().map(DateTimeRef).serialize(serializer)
}

#[cfg(test)]
mod tests {
    use time::{OffsetDateTime, UtcOffset};

    use crate::{
        kmip_0::kmip_messages::ResponseMessageHeader,
        ttlv::{TTLValue, from_ttlv, to_ttlv},
    };

    fn time_stamp_value(time_stamp: OffsetDateTime) -> (TTLValue, ResponseMessageHeader) {
        let header = ResponseMessageHeader {
            time_stamp,
            ..Default::default()
        };
        let ttlv = to_ttlv(&header).unwrap();
        let value = match &ttlv.value {
            TTLValue::Structure(fields) => fields.iter().find(|f| f.tag == "TimeStamp"),
            _ => None,
        }
        .unwrap()
        .value
        .clone();
        (value, from_ttlv(ttlv).unwrap())
    }

    #[test]
    fn whole_utc_seconds_and_other_values_round_trip_unchanged() {
        let whole = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let precise = whole
            .replace_nanosecond(123_456_789)
            .unwrap()
            .to_offset(UtcOffset::from_hms(2, 30, 0).unwrap());
        for time_stamp in [whole, precise] {
            let (value, back) = time_stamp_value(time_stamp);
            assert_eq!(value, TTLValue::DateTime(time_stamp));
            assert_eq!(back.time_stamp, time_stamp);
            assert_eq!(back.time_stamp.offset(), time_stamp.offset());
        }
    }
}
