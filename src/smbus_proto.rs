//! The implementation for the SMBus protocol
//!
//! This is the low level packet construction

use crate::base_packet::{MCTPMessageBody, MCTPTransportHeader};
use crate::control_packet::RoutingInformationUpdateEntryType;
use crate::mctp_traits::MCTPHeader;
use smbus_pec::pec;

/// The binary representation of the header version used by SMBus
pub const HDR_VERSION: u8 = 0b001;

/// Indicates that this is an SMBus command code
pub(crate) const MCTP_SMBUS_COMMAND_CODE: u8 = 0x0F;

bitfield! {
    /// The MCTP SMBus/I2C Packet Header
    pub struct MCTPSMBusHeader([u8]);
    u8;
    /// SMBus R/W# bit: Shall be set to 0b as all MCTP messages use SMBus write transactions
    pub dest_read_write, set_dest_read_write: 0, 0;
    /// SMBus Destination Slave Address: The slave address of the target device for the local SMBus link
    pub dest_slave_addr, set_dest_slave_addr : 7, 1;
    /// Command Code: SMBus Command Code
    pub command_code, set_command_code: 15, 8;
    /// Byte Count: Byte count for the SMBus Block Write protocol transaction that is carrying the MCTP packet content.
    pub byte_count, set_byte_count: 23, 16;
    /// This bit shall be set to 1b. The value enables MCTP to be differentiated from IPMI over SMBus and IPMB (IPMI over I2C) protocols.
    pub source_read_write, set_source_read_write: 24, 24;
    /// For the local SMBus link, the slave address of the source device.
    pub source_slave_addr, set_source_slave_addr: 31, 25;
}

impl MCTPSMBusHeader<[u8; 4]> {
    /// Create a new MCTPSMBusHeader
    pub fn new() -> Self {
        let buf = [0; 4];
        MCTPSMBusHeader(buf)
    }

    /// Create a new `MCTPSMBusHeader` from an existing buffer.
    ///
    /// `buffer`: The existing buffer for the `MCTPSMBusHeader`
    /// No checks are performed on the `buffer`.
    pub fn new_from_buf(buf: [u8; 4]) -> Self {
        MCTPSMBusHeader(buf)
    }
}

impl Default for MCTPSMBusHeader<[u8; 4]> {
    fn default() -> Self {
        Self::new()
    }
}

/// The final constructed SMBus packet.
pub(crate) struct MCTPSMBusPacket<'a, 'b> {
    smbus_header: &'a mut MCTPSMBusHeader<[u8; 4]>,
    base_header: &'a MCTPTransportHeader,
    data_bytes: &'a MCTPMessageBody<'a, 'b>,
}

impl<'a, 'b> MCTPSMBusPacket<'a, 'b> {
    /// Create a new SMBUs packet
    pub fn new(
        smbus_header: &'a mut MCTPSMBusHeader<[u8; 4]>,
        base_header: &'a MCTPTransportHeader,
        data_bytes: &'b MCTPMessageBody,
    ) -> Self {
        let mut packet = Self {
            smbus_header,
            base_header,
            data_bytes,
        };

        packet.finalise();

        packet
    }

    /// Finalise the creation of the SMBus packet
    ///
    /// Currently this just sets the total byte count.
    fn finalise(&mut self) {
        self.smbus_header.set_byte_count(self.len() as u8 - 4);
    }
}

impl<'a, 'b> MCTPHeader for MCTPSMBusPacket<'a, 'b> {
    /// Return the number of bytes used by the packet.
    fn len(&self) -> usize {
        let mut size = 0;

        size += 4;
        size += 4;
        size += self.data_bytes.len();
        size += 1;

        size
    }

    /// Store the `MCTPSMBusPacket` packet into a buffer and return
    /// the number of bytes stored. The return value is the same as
    /// calling `len()`.
    ///
    /// `buffer`: a mutable buffer to store the bytes from the struct.
    /// `buffer` is formated as valid MCTP data.
    fn to_raw_bytes(&self, buf: &mut [u8]) -> usize {
        let mut size = 0;

        buf[0..4].copy_from_slice(&self.smbus_header.0);
        size += 4;

        buf[4..8].copy_from_slice(&self.base_header.to_bytes());
        size += 4;

        size += self.data_bytes.to_raw_bytes(&mut buf[size..]);

        buf[size] = pec(&buf[0..size]);
        size += 1;

        size
    }
}

bitfield! {
    /// The MCTP SMBus/I2C Routing Information Update Entry Format
    pub struct SMBusRoutingInformationUpdateEntry([u8]);
    u8;
    /// Entry Type
    pub entry_type, set_entry_type: 3, 0;
    _rsvd, _: 7, 4;
    /// Size of EID Range. The count of EIDs in the range.
    pub eid_range_size, set_eid_range_size: 15, 8;
    /// First EID in EID Range
    pub first_eid, set_first_eid: 23, 16;
    /// Physical address
    pub physical_address, set_physical_address: 31, 24;
}

impl SMBusRoutingInformationUpdateEntry<[u8; 4]> {
    /// Create a new SMBusRoutingInformationUpdateEntry.
    pub fn new(
        entry_type: RoutingInformationUpdateEntryType,
        range_size: u8,
        first_eid: u8,
        physical_address: u8,
    ) -> Self {
        let buf = [0; 4];
        let mut format = SMBusRoutingInformationUpdateEntry(buf);

        format.set_entry_type(entry_type as u8);
        format.set_eid_range_size(range_size);
        format.set_first_eid(first_eid);
        format.set_physical_address(physical_address);

        format
    }

    /// Create a new `SMBusRoutingInformationUpdateEntry` from an existing buffer.
    ///
    /// `buffer`: The existing buffer for the `SMBusRoutingInformationUpdateEntry`
    /// No checks are performed on the `buffer`.
    pub fn new_from_buf(buf: [u8; 4]) -> Self {
        SMBusRoutingInformationUpdateEntry(buf)
    }
}
