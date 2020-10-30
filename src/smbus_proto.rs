//! The implementation for the SMBus protocol
//!
//! This is the low level packet construction

use crate::base_packet::{MCTPMessageBody, MCTPTransportHeader};
use crate::mctp_traits::MCTPHeader;

/// The header version used by SMBus
pub const HDR_VERSION: u8 = 0b001;

/// INdicates that this is an SMBus command code
pub(crate) const MCTP_SMBUS_COMMAND_CODE: u8 = 0x0F;

bitfield! {
    /// The MCTP SMBus/I2C Packet Header
    pub struct MCTPSMBusHeader([u8]);
    u8;
    /// SMBus R/W# bit:Shall be set to 0b as all MCTP messages use SMBus write transactions
    pub dest_read_write, set_dest_read_write: 0, 0;
    /// SMBus Destination Slave Address:The slave address of the target device for the local SMBus link
    pub dest_slave_addr, set_dest_slave_addr : 7, 1;
    /// Command Code:SMBus Command Code
    pub command_code, set_command_code: 15, 8;
    /// Byte Count:Byte count for the SMBus Block Write protocol transaction that is carrying the MCTP packet content.
    pub byte_count, set_byte_count: 23, 16;
    /// This bit shall be set to 1b. The value enables MCTP to be differentiated from IPMI over SMBus and IPMB (IPMI over I2C) protocols.
    pub source_read_write, set_source_read_write: 24, 24;
    /// For the local SMBus link, the slave address of the source device.
    pub source_slave_addr, set_source_slave_addr: 30, 25;
}

impl MCTPSMBusHeader<[u8; 4]> {
    /// Create a new MCTPSMBusHeader
    pub fn new() -> Self {
        let buf = [0; 4];
        MCTPSMBusHeader(buf)
    }

    /// Create a new MCTPSMBusHeader from an already existing buffer
    pub fn new_from_buf(buf: [u8; 4]) -> Self {
        MCTPSMBusHeader(buf)
    }
}

impl Default for MCTPSMBusHeader<[u8; 4]> {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) struct MCTPSMBusPacket<'a> {
    smbus_header: MCTPSMBusHeader<[u8; 4]>,
    base_header: MCTPTransportHeader<[u8; 4]>,
    data_bytes: &'a MCTPMessageBody<'a>,
}

impl<'a> MCTPSMBusPacket<'a> {
    pub fn new(
        smbus_header: MCTPSMBusHeader<[u8; 4]>,
        base_header: MCTPTransportHeader<[u8; 4]>,
        data_bytes: &'a MCTPMessageBody,
    ) -> Self {
        let mut packet = Self {
            smbus_header,
            base_header,
            data_bytes,
        };

        packet.finalise();

        packet
    }

    fn finalise(&mut self) {
        self.smbus_header.set_byte_count(self.len() as u8 - 3);
    }
}

impl<'a> MCTPHeader for MCTPSMBusPacket<'a> {
    /// Return the number of bytes used by the packet.
    fn len(&self) -> usize {
        let mut size = 0;

        size += 4;
        size += 4;
        size += self.data_bytes.len();

        size
    }

    /// Store the MCTPSMBusPacket packet into a buffer.
    fn to_raw_bytes(&self, buf: &mut [u8]) -> usize {
        let mut size = 0;

        buf[0..4].copy_from_slice(&self.smbus_header.0);
        size += 4;

        buf[4..8].copy_from_slice(&self.base_header.0);
        size += 4;

        size += self.data_bytes.to_raw_bytes(&mut buf[size..]);

        size
    }
}
