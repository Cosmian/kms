// Copyright 2024 Cosmian Tech SAS
// Changes made to the original code are
// licensed under the Business Source License version 1.1.

//! `CKO_DATA` object as defined in PKCS#11 2.40 4.5
//! [PKCS#11 2.40 ~ 4.5](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959706)

use zeroize::{Zeroize, Zeroizing};

pub trait DataObject: Zeroize + Send + Sync {
    /// The unique identifier of the object (in the KMS)
    fn remote_id(&self) -> &str;
    /// The value of the object which may be a secret
    fn value(&self) -> Zeroizing<Vec<u8>>;
    /// The application that manages the object
    fn application(&self) -> Vec<u8>;
    fn data_hash(&self) -> Vec<u8>;
}
