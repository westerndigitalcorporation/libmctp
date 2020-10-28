//! Traits used for the MCTP implementation

/// The standard trait for all MCTP headers
pub(crate) trait MCTPHeader {
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn to_raw_bytes(&self, buf: &mut [u8]) -> usize;
}
