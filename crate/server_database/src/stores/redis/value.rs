//! This is the replacement for the deprecated `Location` struct from `cloudproof_findex`.

use std::fmt::Display;

/// Implements the functionalities of a byte-vector.
///
/// # Parameters
///
/// - `type_name`   : name of the byte-vector type
macro_rules! impl_byte_vector {
    ($type_name:ty) => {
        impl AsRef<[u8]> for $type_name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        // impl Deref for $type_name {
        //     type Target = [u8];

        //     fn deref(&self) -> &Self::Target {
        //         &self.0
        //     }
        // }

        // impl DerefMut for $type_name {
        //     fn deref_mut(&mut self) -> &mut <Self as Deref>::Target {
        //         &mut self.0
        //     }
        // }

        impl<'a> From<&'a [u8]> for $type_name {
            fn from(bytes: &'a [u8]) -> Self {
                Self(bytes.to_vec())
            }
        }

        impl From<Vec<u8>> for $type_name {
            fn from(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }
        }

        impl From<&str> for $type_name {
            fn from(bytes: &str) -> Self {
                bytes.as_bytes().into()
            }
        }

        impl From<$type_name> for Vec<u8> {
            fn from(var: $type_name) -> Self {
                var.0
            }
        }

        // impl Serializable for $type_name {
        //     type Error = $crate::error::CoreError;

        //     fn length(&self) -> usize {
        //         self.len()
        //     }

        //     fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        //         ser.write_vec(&self).map_err(Self::Error::from)
        //     }

        //     fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        //         Ok(Self::from(de.read_vec()?))
        //     }

        //     fn serialize(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, Self::Error> {
        //         // don't call `write()` to avoir writing size
        //         Ok(self.0.to_vec().into())
        //     }

        //     fn deserialize(bytes: &[u8]) -> Result<Self, Self::Error> {
        //         // don't call `read()` since there is no leading size
        //         Ok(Self(bytes.to_vec()))
        //     }
        // }
    };
}

#[must_use]
#[derive(Clone, Debug, Hash, Default, PartialEq, Eq)]
pub struct Value(Vec<u8>);
impl_byte_vector!(Value);
// TODO(important): I took the original Location implementaion and created this `Value` to replace it as the Location concept is obsolete.
// Yet, I am not sure we need all what's inside this macro below - and it's complicated to code with
// I would rather simply get rid of it and implement exactly AND ONLY what we need.
// Another question raises: the Vec<u8> is unbounded in size, do we want to limit it to a certain size ?

impl Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Value: {}", self)
    }
}

// trash
// define_byte_type!(Bytes);

// // Define a byte type, and use `Value` as an alias for 8-bytes values of
// // that type.
// pub(crate) type Value = Bytes<8>;

// macro_rules! impl_byte_array {
//     ($type_name:ident) => {
//         impl<const LENGTH: usize> AsRef<[u8]> for $type_name<LENGTH> {
//             fn as_ref(&self) -> &[u8] {
//                 &self.0
//             }
//         }

//         impl<const LENGTH: usize> std::ops::Deref for $type_name<LENGTH> {
//             type Target = [u8];

//             fn deref(&self) -> &Self::Target {
//                 &self.0
//             }
//         }

//         impl<const LENGTH: usize> std::ops::DerefMut for $type_name<LENGTH> {
//             fn deref_mut(&mut self) -> &mut Self::Target {
//                 &mut self.0
//             }
//         }

//         impl<const LENGTH: usize> From<[u8; LENGTH]> for $type_name<LENGTH> {
//             fn from(bytes: [u8; LENGTH]) -> Self {
//                 Self(bytes)
//             }
//         }

//         impl<const LENGTH: usize> From<$type_name<LENGTH>> for [u8; LENGTH] {
//             fn from(var: $type_name<LENGTH>) -> Self {
//                 var.0
//             }
//         }

//         impl<const LENGTH: usize> Serializable for $type_name<LENGTH> {
//             type Error = $crate::error::CoreError;

//             fn length(&self) -> usize {
//                 LENGTH
//             }

//             fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
//                 ser.write_array(&self).map_err(Self::Error::from)
//             }

//             fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
//                 Ok(Self::from(de.read_array()?))
//             }
//         }
//     };
// }
