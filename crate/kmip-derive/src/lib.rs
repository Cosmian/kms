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
/// serde will loose the variant value, and only serialize the variant name
/// with the default Serialize implementation.
///
/// `KmipEnumSerialize` will serialize the variant name and value.
///
/// It accomplishes this using two "tricks":
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
