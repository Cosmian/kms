use serde::{Deserializer, de::IgnoredAny};
use time::macros::datetime;

use super::OffsetDateTimeDeserializer;

fn de() -> OffsetDateTimeDeserializer {
    OffsetDateTimeDeserializer::new("ActivationDate", datetime!(2024-03-05 12:34:56 UTC))
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_any_unsupported() {
    drop((&mut de()).deserialize_any(IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_bool_unsupported() {
    drop((&mut de()).deserialize_bool(IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_i64_unsupported() {
    drop((&mut de()).deserialize_i64(IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_u64_unsupported() {
    drop((&mut de()).deserialize_u64(IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_f32_unsupported() {
    drop((&mut de()).deserialize_f32(IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_f64_unsupported() {
    drop((&mut de()).deserialize_f64(IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_char_unsupported() {
    drop((&mut de()).deserialize_char(IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_str_unsupported() {
    drop((&mut de()).deserialize_str(IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_string_unsupported() {
    drop((&mut de()).deserialize_string(IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_bytes_unsupported() {
    drop((&mut de()).deserialize_bytes(IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_byte_buf_unsupported() {
    drop((&mut de()).deserialize_byte_buf(IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_option_unsupported() {
    drop((&mut de()).deserialize_option(IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_unit_unsupported() {
    drop((&mut de()).deserialize_unit(IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_unit_struct_unsupported() {
    drop((&mut de()).deserialize_unit_struct("X", IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_newtype_struct_unsupported() {
    drop((&mut de()).deserialize_newtype_struct("X", IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_seq_unsupported() {
    drop((&mut de()).deserialize_seq(IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_tuple_unsupported() {
    drop((&mut de()).deserialize_tuple(1, IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_tuple_struct_unsupported() {
    drop((&mut de()).deserialize_tuple_struct("X", 1, IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_map_unsupported() {
    drop((&mut de()).deserialize_map(IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_struct_unsupported() {
    drop((&mut de()).deserialize_struct("X", &[], IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_enum_unsupported() {
    drop((&mut de()).deserialize_enum("X", &[], IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_identifier_unsupported() {
    drop((&mut de()).deserialize_identifier(IgnoredAny));
}

#[test]
#[should_panic(expected = "should not be called by OffsetDateTime deserializer")]
fn characterization_offset_date_time_deserializer_ignored_any_unsupported() {
    drop((&mut de()).deserialize_ignored_any(IgnoredAny));
}
