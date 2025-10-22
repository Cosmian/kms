//! KMIP XML utilities (under `ttlv::xml`).
//!
//! Re-exports only. Implementation lives in `serializer.rs` and `parser.rs`.
//!
//! Public API:
//! * `TTLVXMLSerializer`, `TTLVXMLDeserializer`
//! * `KmipXmlDoc` with `new` and `new_with_file`
#![allow(clippy::box_default)]

mod deserializer;
mod serializer;
pub use deserializer::TTLVXMLDeserializer;
pub use serializer::TTLVXMLSerializer;

mod parser;
pub use parser::KmipXmlDoc;

#[cfg(test)]
mod tests;
