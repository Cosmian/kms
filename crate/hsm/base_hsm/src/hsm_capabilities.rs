
#[derive(Debug, Clone, Default)]
pub struct HsmCapabilities {
    /// Maximum data size before switching to AES CBC multi-round operations (in bytes)
    pub max_cbc_data_size: Option<usize>,
}

pub trait HsmProvider: Send + Sync + 'static {
    fn capabilities() -> HsmCapabilities;
}