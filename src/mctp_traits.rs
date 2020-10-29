//! Traits used for the MCTP implementation.
//!
//! This is an internal implementation.

/// The standard trait for all MCTP headers
pub(crate) trait MCTPHeader {
    /// Return the number of bytes in the header
    fn len(&self) -> usize;

    /// Check if the header is empty
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Convert the header to raw bytes
    fn to_raw_bytes(&self, buf: &mut [u8]) -> usize;
}
