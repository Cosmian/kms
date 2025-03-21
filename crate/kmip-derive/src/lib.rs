use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

/// Serialize a KMIP enum variant with both the variant name and value.
/// The name and the value are part of the KMIP specification. The name is used
/// when serializing to TTLV JSON, and the value is used when serializing to TTLV bytes.
///
/// # Usage
/// ```Rust
/// #[derive(Deserialize, KmipEnumSerialize, Copy, Clone, strum::IntoStaticStr])
/// #[repr(u32)]
/// pub enum ObjectType {
///   Certificate = 0x00000001,
///   SymmetricKey = 0x00000002,
/// }
/// ```
/// Please note that:
/// - The enum must derive `Copy` and `strum::IntoStaticStr` in addition to `KmipEnumSerialize`.
/// - The enum must be `repr(u32)`.
///
/// # Explanation
///
/// When serializing enum with variant name and value, such as:
/// ```Rust
/// pub enum ObjectType {
///   Certificate = 0x00000001,
///   SymmetricKey = 0x00000002,
/// }
/// ```
/// serde will lose the variant value, and only serialize the variant name
/// with the default Serialize implementation.
///
/// `KmipEnumSerialize` will serialize the variant name and value.
///
/// It achieves this using two "tricks":
/// 1. With the help of `strum::IntoStaticStr`, it converts the variant name to a static string
///    required by `serde::Serialize::serialize_unit_variant`.
/// 2. It uses `*self as u32` to get the variant value, which requires the enum to derive
///    the `Copy` trait. The value is then inserted in lieu of the index value, which is normally
///    just a counter over the variants starting at 0.
#[proc_macro_derive(KmipEnumSerialize)]
pub fn kmip_serialize_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let expanded = quote! {
        impl Serialize for #name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                // Get the variant name as a static string using strum::IntoStaticStr
                let variant_name: &'static str = self.into();
                // Get the variant value as u32 using `Copy`
                let variant_value: u32 = *self as u32;
                serializer.serialize_unit_variant(stringify!(#name), variant_value, variant_name)
            }
        }
    };

    TokenStream::from(expanded)
}

/// Deserialize a KMIP enum variant from either the variant value or name.
/// The macro supports deserializing from:
/// 1. The numeric value (using strum::FromRepr)
/// 2. The string name (using std::str::FromStr)
///
/// # Usage
/// ```Rust
/// #[derive(KmipEnumSerialize, KmipEnumDeserialize, EnumString, FromRepr, Copy, Clone)]
/// #[repr(u32)]
/// pub enum ObjectType {
///   Certificate = 0x00000001,
///   SymmetricKey = 0x00000002,
/// }
/// ```
///
/// Please note that:
/// - The enum must derive `strum::FromRepr` for numeric deserialization
/// - The enum must derive `std::str::FromStr` (usually via `strum::EnumString`) for string deserialization
/// - The enum must be `repr(u32)`
#[proc_macro_derive(KmipEnumDeserialize)]
pub fn kmip_deserialize_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let expanded = quote! {
        impl<'de> Deserialize<'de> for #name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                // Deserialize either a number or a string
                struct EnumVisitor;

                impl<'de> serde::de::Visitor<'de> for EnumVisitor {
                    type Value = #name;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str(concat!("a ", stringify!(#name), " variant as a u32 or string"))
                    }

                    // Handle u32 deserialization using strum::FromRepr
                    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        use strum::FromRepr;
                        let value = value as u32;
                        #name::from_repr(value).ok_or_else(|| {
                            E::invalid_value(
                                serde::de::Unexpected::Unsigned(value as u64),
                                &concat!("valid ", stringify!(#name), " value"),
                            )
                        })
                    }
                    // Handle string deserialization using std::str::FromStr
                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        use std::str::FromStr;
                        #name::from_str(value).map_err(|_| {
                            E::invalid_value(
                                serde::de::Unexpected::Str(value),
                                &concat!("valid ", stringify!(#name), " name"),
                            )
                        })
                    }
                    // Handle string deserialization using std::str::FromStr
                    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        self.visit_str(&value)
                    }
                }
                deserializer.deserialize_any(EnumVisitor)
            }
        }
    };
    TokenStream::from(expanded)
}

/// A convenience macro attribute that automatically adds all necessary derives and representations
/// for KMIP enum types.
///
/// # Usage
/// ```rust
/// use kmip_derive::kmip_enum;
///
/// #[kmip_enum]
/// pub enum ObjectType {
///     Certificate = 0x00000001,
///     SymmetricKey = 0x00000002,
/// }
/// ```
///
/// # Features
/// This attribute does the following:
/// 1. Adds `#[repr(u32)]` to the enum automatically
/// 2. Adds the following derive macros:
///    - `KmipEnumSerialize` and `KmipEnumDeserialize` for KMIP-specific serialization
///    - Common traits: `Copy`, `Clone`, `Debug`, `Eq`, `PartialEq`
///    - String conversion: `Display`
///    - Strum traits: `EnumString`, `IntoStaticStr`, and `FromRepr` for name/value conversions
///
/// This simplifies the definition of KMIP enums by combining all necessary derives into a single attribute.
#[proc_macro_attribute]
pub fn kmip_enum(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut input = parse_macro_input!(item as DeriveInput);

    // Add repr(u32) attribute if not already present
    let repr_attr = syn::parse_quote!(#[repr(u32)]);
    input.attrs.push(repr_attr);

    // Create the additional derives
    let expanded = quote! {
        #[derive(
            KmipEnumSerialize,
            KmipEnumDeserialize,
            Copy,
            Clone,
            Debug,
            Eq,
            PartialEq,
            Display,
            Hash,
            strum::EnumString,
            strum::EnumIter,
            strum::IntoStaticStr,
            strum::FromRepr
        )]
        #[allow(non_camel_case_types)]
        #input
    };

    TokenStream::from(expanded)
}
