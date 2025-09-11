use pkcs11_sys::CK_ULONG;

#[derive(Debug, Clone)]
pub struct HsmCapabilities {
    /// Maximum data size before switching to AES CBC multi-round operations (in bytes)
    /// If `None`, there is no enforced limit.
    pub max_cbc_data_size: Option<usize>,

    /// Maximum number of objects that can be returned by a single FindObjects operation
    /// (also known as `ulMaxObjectCount` in PKCS#11).
    pub find_max_object_count: CK_ULONG,
}

impl Default for HsmCapabilities {
    fn default() -> Self {
        HsmCapabilities {
            max_cbc_data_size: None,
            find_max_object_count: 1,
        }
    }
}

pub trait HsmProvider: Send + Sync + 'static {
    fn capabilities() -> HsmCapabilities;
}
