//! TTLV -> deterministic test XML serializer utilities.
//!
//! `TTLVXMLDeserializer` has been moved to `deserializer.rs`.

use quick_xml::{
    Writer,
    events::{BytesStart, Event},
};

use crate::{
    KmipError,
    ttlv::{TTLV, TTLValue},
};

pub struct TTLVXMLSerializer;
impl TTLVXMLSerializer {
    pub fn to_xml(ttlv: &TTLV) -> Result<String, KmipError> {
        let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);
        Self::write_ttlv(&mut writer, ttlv)?;
        let bytes = writer.into_inner();
        String::from_utf8(bytes).map_err(|e| KmipError::Default(format!("utf8: {e}")))
    }

    fn write_ttlv(w: &mut Writer<Vec<u8>>, ttlv: &TTLV) -> Result<(), KmipError> {
        match &ttlv.value {
            TTLValue::Structure(children) => {
                let mut elem = BytesStart::new(ttlv.tag.as_str());
                elem.push_attribute(("type", "Structure"));
                w.write_event(Event::Start(elem))
                    .map_err(|e| KmipError::Default(format!("xml write: {e}")))?;
                for c in children {
                    Self::write_ttlv(w, c)?;
                }
                w.write_event(Event::End(BytesStart::new(ttlv.tag.as_str()).to_end()))
                    .map_err(|e| KmipError::Default(format!("xml write: {e}")))?;
            }
            primitive => {
                let mut elem = BytesStart::new(ttlv.tag.as_str());
                match primitive {
                    TTLValue::Integer(v) => {
                        elem.push_attribute(("type", "Integer"));
                        let val = v.to_string();
                        elem.push_attribute(("value", val.as_str()));
                    }
                    TTLValue::LongInteger(v) => {
                        elem.push_attribute(("type", "LongInteger"));
                        let val = v.to_string();
                        elem.push_attribute(("value", val.as_str()));
                    }
                    TTLValue::BigInteger(_) => {
                        elem.push_attribute(("type", "BigInteger"));
                        elem.push_attribute(("value", ""));
                    }
                    TTLValue::Enumeration(evar) => {
                        elem.push_attribute(("type", "Enumeration"));
                        let val = evar.value.to_string();
                        elem.push_attribute(("value", val.as_str()));
                        if !evar.name.is_empty() {
                            elem.push_attribute(("name", evar.name.as_str()));
                        }
                    }
                    TTLValue::Boolean(b) => {
                        elem.push_attribute(("type", "Boolean"));
                        elem.push_attribute(("value", if *b { "true" } else { "false" }));
                    }
                    TTLValue::TextString(s) => {
                        elem.push_attribute(("type", "TextString"));
                        elem.push_attribute(("value", s.as_str()));
                    }
                    TTLValue::ByteString(bytes) => {
                        elem.push_attribute(("type", "ByteString"));
                        let val = hex::encode(bytes);
                        elem.push_attribute(("value", val.as_str()));
                    }
                    TTLValue::DateTime(dt) => {
                        elem.push_attribute(("type", "DateTime"));
                        let val = dt.unix_timestamp().to_string();
                        elem.push_attribute(("value", val.as_str()));
                    }
                    TTLValue::Interval(i) => {
                        elem.push_attribute(("type", "Interval"));
                        let val = i.to_string();
                        elem.push_attribute(("value", val.as_str()));
                    }
                    TTLValue::DateTimeExtended(i) => {
                        elem.push_attribute(("type", "DateTimeExtended"));
                        let val = i.to_string();
                        elem.push_attribute(("value", val.as_str()));
                    }
                    TTLValue::Structure(_) => {
                        return Err(KmipError::Default(
                            "cannot serialize Structure as an empty XML element".into(),
                        ));
                    }
                }
                w.write_event(Event::Empty(elem))
                    .map_err(|e| KmipError::Default(format!("xml write: {e}")))?;
            }
        }
        Ok(())
    }
}
