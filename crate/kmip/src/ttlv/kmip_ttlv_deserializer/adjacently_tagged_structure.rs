use std::sync::RwLock;

use cosmian_logger::trace;
use serde::de::{DeserializeSeed, MapAccess};
use tracing::instrument;

use super::TtlvDeserializer;
use crate::ttlv::{
    KmipEnumerationVariant, TTLV, TTLValue, TtlvError,
    kmip_ttlv_deserializer::deserializer::MapAccessState,
};

#[derive(Debug, PartialEq, Eq)]
enum State {
    Tag,
    Content,
    Done,
}

/// The `AdjacentlyTaggedStructure` is used to deserialize an Adjacently tagged structure (actually an enum)
/// with a tag and a content.
/// A typical such structure is the `VendorAttributeValue` structure.
///
/// In TTLV, the adjacently tagged structure is represented as a single TTLV with a tag and a value.
/// This is done in the `collapse_adjacently_tagged_structure()` function of the KMIP TTLV serializer.
///
/// Since collapsing looses the name of the enum variant, for this to work, the variant names
/// of the adjacently tagged enum must match the TTLV Value types EXACTLY, e.g. `BigInteger`, `Structure`, etc.
///
/// This walker converts
///
/// ```
/// TTLV {
/// tag: "VendorAttributeValue",
/// value: BigInteger(
///     KmipBigInt(
///         BigInt {
///             sign: Plus,
///             data: BigUint {
///                 data: [
///                     3197704712,
///                     28,
///                 ],
///             },
///         },
///     ),
/// )
/// ```
///
/// into
///
/// ```
/// TTLV {®
/// tag: "VendorAttributeValue",
/// value: Structure(
///     [
///         TTLV {
///             tag: "BigInteger",
///             value: Enumeration(
///                 KmipEnumerationVariant {
///                     value: "0x00000002",
///                     name: "BigInteger",
///                 },
///             ),
///         },
///         TTLV {
///             tag: "_c",
///             value: BigInteger(
///                 KmipBigInt(
///                     BigInt {
///                         sign: Plus,
///                         data: BigUint {
///                            data: [
///                                 3197704712,
///                                 28,
///                             ],
///                         },
///                     },
///                 ),
///             ),
///         },
///     ],
/// ),
/// }
/// ```
pub(super) struct AdjacentlyTaggedStructure {
    state: State,
    tag: TTLV,
    content: TTLV,
}

impl AdjacentlyTaggedStructure {
    #[instrument(level = "trace", skip(current))]
    pub(super) fn new(current: &TTLV) -> Self {
        let (tag, content) = match &current.value {
            TTLValue::Structure(ttlvs) => (
                TTLV {
                    tag: "Structure".into(),
                    value: TTLValue::Enumeration(KmipEnumerationVariant {
                        value: 0,
                        name: "Structure".into(),
                    }),
                },
                further_expand_ttlv_struct(ttlvs.first().unwrap_or(&TTLV {
                    tag: "ERROR".into(),
                    value: TTLValue::TextString(
                        "There should be one TTLV in the Structure".to_owned(),
                    ),
                })),
            ),
            TTLValue::Integer(v) => (
                TTLV {
                    tag: "Integer".into(),
                    value: TTLValue::Enumeration(KmipEnumerationVariant {
                        value: 0,
                        name: "Integer".into(),
                    }),
                },
                TTLV {
                    tag: "_c".into(),
                    value: TTLValue::Integer(*v),
                },
            ),
            TTLValue::LongInteger(v) => (
                TTLV {
                    tag: "LongInteger".into(),
                    value: TTLValue::Enumeration(KmipEnumerationVariant {
                        value: 0,
                        name: "LongInteger".into(),
                    }),
                },
                TTLV {
                    tag: "_c".into(),
                    value: TTLValue::LongInteger(*v),
                },
            ),
            TTLValue::BigInteger(kmip_big_int) => (
                TTLV {
                    tag: "BigInteger".into(),
                    value: TTLValue::Enumeration(KmipEnumerationVariant {
                        value: 0,
                        name: "BigInteger".into(),
                    }),
                },
                TTLV {
                    tag: "_c".into(),
                    value: TTLValue::BigInteger(kmip_big_int.clone()),
                },
            ),
            TTLValue::Enumeration(kmip_enumeration_variant) => (
                TTLV {
                    tag: "Enumeration".into(),
                    value: TTLValue::Enumeration(KmipEnumerationVariant {
                        value: 0,
                        name: "Enumeration".into(),
                    }),
                },
                TTLV {
                    tag: "_c".into(),
                    value: TTLValue::Enumeration(kmip_enumeration_variant.clone()),
                },
            ),
            TTLValue::Boolean(v) => (
                TTLV {
                    tag: "Boolean".into(),
                    value: TTLValue::Enumeration(KmipEnumerationVariant {
                        value: 0,
                        name: "Boolean".into(),
                    }),
                },
                TTLV {
                    tag: "_c".into(),
                    value: TTLValue::Boolean(*v),
                },
            ),
            TTLValue::TextString(s) => (
                TTLV {
                    tag: "TextString".into(),
                    value: TTLValue::Enumeration(KmipEnumerationVariant {
                        value: 0,
                        name: "TextString".into(),
                    }),
                },
                TTLV {
                    tag: "_c".into(),
                    value: TTLValue::TextString(s.clone()),
                },
            ),
            TTLValue::ByteString(items) => (
                TTLV {
                    tag: "ByteString".into(),
                    value: TTLValue::Enumeration(KmipEnumerationVariant {
                        value: 0,
                        name: "ByteString".into(),
                    }),
                },
                TTLV {
                    tag: "_c".into(),
                    value: TTLValue::ByteString(items.clone()),
                },
            ),
            TTLValue::DateTime(offset_date_time) => (
                TTLV {
                    tag: "DateTime".into(),
                    value: TTLValue::Enumeration(KmipEnumerationVariant {
                        value: 0,
                        name: "DateTime".into(),
                    }),
                },
                TTLV {
                    tag: "_c".into(),
                    value: TTLValue::DateTime(*offset_date_time),
                },
            ),
            TTLValue::Interval(v) => (
                TTLV {
                    tag: "Interval".into(),
                    value: TTLValue::Enumeration(KmipEnumerationVariant {
                        value: 0,
                        name: "Interval".into(),
                    }),
                },
                TTLV {
                    tag: "_c".into(),
                    value: TTLValue::Interval(*v),
                },
            ),
            TTLValue::DateTimeExtended(dt) => (
                TTLV {
                    tag: "DateTimeExtended".into(),
                    value: TTLValue::Enumeration(KmipEnumerationVariant {
                        value: 0,
                        name: "DateTimeExtended".into(),
                    }),
                },
                TTLV {
                    tag: "_c".into(),
                    value: TTLValue::DateTimeExtended(*dt),
                },
            ),
        };

        trace!("tag: {:?}, content: {:?}", tag, content,);

        Self {
            state: State::Tag,
            tag,
            content,
        }
    }
}

/// When we have a TTLV in the Structure variant, ti is compressed by the serializer (left as such)
/// However, we need to expand it to a TTLV with a tag, a type and a value for the deserializer
fn further_expand_ttlv_struct(ttlv: &TTLV) -> TTLV {
    TTLV {
        tag: "_c".into(),
        value: TTLValue::Structure(vec![
            TTLV {
                tag: "tag".into(),
                value: TTLValue::TextString(ttlv.tag.to_string()),
            },
            TTLV {
                tag: "type".into(),
                value: TTLValue::TextString(match ttlv.value {
                    TTLValue::Structure(_) => "Structure".to_owned(),
                    TTLValue::Integer(_) => "Integer".to_owned(),
                    TTLValue::LongInteger(_) => "LongInteger".to_owned(),
                    TTLValue::BigInteger(_) => "BigInteger".to_owned(),
                    TTLValue::Enumeration(_) => "Enumeration".to_owned(),
                    TTLValue::Boolean(_) => "Boolean".to_owned(),
                    TTLValue::TextString(_) => "TextString".to_owned(),
                    TTLValue::ByteString(_) => "ByteString".to_owned(),
                    TTLValue::DateTime(_) => "DateTime".to_owned(),
                    TTLValue::Interval(_) => "Interval".to_owned(),
                    TTLValue::DateTimeExtended(_) => "DateTimeExtended".to_owned(),
                }),
            },
            TTLV {
                tag: "value".into(),
                value: ttlv.value.clone(),
            },
        ]),
    }
}

// MapAccess is called when deserializing a struct because deserialize_struct called visit_map
// The current input is the top structure holding an array of TTLVs which are the fields of the struct/map.
// The calls to `next_value` are driven by the visitor,
// and it is up to this Access to synchronize and advance its counter
// over the struct fields (`self.index`) in this case
impl<'de> MapAccess<'de> for AdjacentlyTaggedStructure {
    type Error = TtlvError;

    #[instrument(level = "trace", skip(self, seed))]
    fn next_key_seed<K>(&mut self, seed: K) -> std::result::Result<Option<K::Value>, Self::Error>
    where
        K: DeserializeSeed<'de>,
    {
        trace!("Key: State ? {:?}", self.state);

        if self.state == State::Done {
            return Ok(None);
        }
        if self.state == State::Tag {
            return seed
                .deserialize(&mut TtlvDeserializer {
                    map_state: MapAccessState::Key,
                    child_index: 0,
                    current: &TTLV {
                        tag: "_t".into(),
                        value: TTLValue::TextString("_t".to_owned()),
                    },
                    at_root: RwLock::new(true),
                })
                .map(Option::Some);
        }

        seed.deserialize(&mut TtlvDeserializer {
            map_state: MapAccessState::Key,
            child_index: 0,
            current: &TTLV {
                tag: "_c".into(),
                value: TTLValue::TextString("_c".to_owned()),
            },
            at_root: RwLock::new(true),
        })
        .map(Option::Some)
    }

    #[instrument(level = "trace", skip(self, seed))]
    fn next_value_seed<V>(&mut self, seed: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        trace!("Value: State ? {:?}", self.state);

        if self.state == State::Tag {
            self.state = State::Content;
            return seed.deserialize(&mut TtlvDeserializer {
                map_state: MapAccessState::Value,
                child_index: 0,
                current: &self.tag,
                at_root: RwLock::new(true),
            });
        }
        self.state = State::Done;

        seed.deserialize(&mut TtlvDeserializer {
            map_state: MapAccessState::Value,
            child_index: 0,
            current: &self.content,
            at_root: RwLock::new(true),
        })
    }

    #[inline]
    fn size_hint(&self) -> Option<usize> {
        Some(2)
    }
}
