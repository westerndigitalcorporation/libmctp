//! The SMBus specific protocol implementation.

use crate::smbus_raw::MCTPSMBusContextRaw;

/// The global context for MCTP SMBus operations
pub struct MCTPSMBusContext {
    raw: MCTPSMBusContextRaw,
}

impl MCTPSMBusContext {
    /// Create a new SBMust context
    ///
    /// `address`: The source address of this device
    pub fn new(address: u8) -> Self {
        Self {
            raw: MCTPSMBusContextRaw::new(address),
        }
    }

    /// Get the underlying raw protocol struct.
    /// This can be used to generate specific packets
    pub fn get_raw(&self) -> &MCTPSMBusContextRaw {
        &self.raw
    }
}
