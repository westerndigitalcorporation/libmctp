//! The SMBus specific CMTP response protocol implementation.

use crate::base_packet::{
    MCTPMessageBody, MCTPMessageBodyHeader, MCTPTransportHeader, MessageType,
};
use crate::control_packet::{CommandCode, CompletionCode, MCTPControlMessageHeader};
use crate::mctp_traits::MCTPHeader;
use crate::smbus_proto::{MCTPSMBusHeader, MCTPSMBusPacket, HDR_VERSION, MCTP_SMBUS_COMMAND_CODE};

/// The context for MCTP SMBus response protocol operations
pub struct MCTPSMBusContextResponse {
    address: u8,
}

impl MCTPSMBusContextResponse {
    /// Create a new SBMust response context
    ///
    /// `address`: The source address of this device
    pub fn new(address: u8) -> Self {
        Self { address }
    }

    fn generate_transport_header(&self, dest_addr: u8) -> MCTPTransportHeader<[u8; 4]> {
        let mut base_header: MCTPTransportHeader<[u8; 4]> = MCTPTransportHeader::new(HDR_VERSION);
        base_header.set_dest_endpoint_id(dest_addr);
        base_header.set_source_endpoint_id(self.address);
        base_header.set_som(true as u8);
        base_header.set_eom(true as u8);
        base_header.set_pkt_seq(0);
        base_header.set_to(true as u8);
        base_header.set_msg_tag(0);

        base_header
    }

    fn generate_smbus_header(&self, dest_addr: u8) -> MCTPSMBusHeader<[u8; 4]> {
        let mut smbus_header: MCTPSMBusHeader<[u8; 4]> = MCTPSMBusHeader::new();
        smbus_header.set_dest_read_write(0);
        smbus_header.set_dest_slave_addr(dest_addr);
        smbus_header.set_command_code(MCTP_SMBUS_COMMAND_CODE);
        smbus_header.set_source_slave_addr(self.address);
        smbus_header.set_source_read_write(1);

        smbus_header
    }

    /// Assigns an EID to the endpoint at the given physical address
    pub fn set_endpoint_id(&self, _dest_addr: u8) -> usize {
        unimplemented!()
    }

    /// Returns the EID presently assigned to an endpoint. Also returns
    /// information about what type the endpoint is and its level of use of
    /// static EIDs.
    pub fn get_endpoint_id(&self, _dest_addr: u8) -> usize {
        unimplemented!()
    }

    /// Retrieves a per-device unique UUID associated withthe endpoint
    pub fn get_endpoint_uuid(&self, _dest_addr: u8) -> usize {
        unimplemented!()
    }

    /// Generate a packet to get the MCTP Versions supported by a device.
    ///
    /// return MCTP base specification version information.
    pub fn get_mctp_version_support(&self, dest_addr: u8, buf: &mut [u8]) -> usize {
        let smbus_header = self.generate_smbus_header(dest_addr);
        let base_header = self.generate_transport_header(dest_addr);

        let header: MCTPMessageBodyHeader<[u8; 1]> =
            MCTPMessageBodyHeader::new(false, MessageType::MCtpControl);
        let command_header =
            MCTPControlMessageHeader::new(false, false, 0, CommandCode::GetMCTPVersionSupport);
        let message_header = Some(&(command_header.0[..]));
        // Return
        // Completion code
        // Version Number entry count: 1
        // Version: 1.3.1
        let message_data: [u8; 6] = [CompletionCode::Success as u8, 1, 0xF1, 0xF3, 0xF1, 0x00];

        let body = MCTPMessageBody::new(header, &message_header, &message_data, None);

        let packet = MCTPSMBusPacket::new(smbus_header, base_header, &body);

        packet.to_raw_bytes(buf)
    }

    /// Lists the message types that an endpoint supports
    pub fn get_message_type_suport(&self, _dest_addr: u8) -> usize {
        unimplemented!()
    }

    /// Used to discover an MCTP endpoint’s vendor-specific MCTP extensions and capabilities
    pub fn get_vendor_defined_message_support(&self, _dest_addr: u8) -> usize {
        unimplemented!()
    }
}

#[cfg(test)]
mod smbus_response_tests {
    use super::*;

    #[test]
    fn test_generate_smbus_header() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x23;

        let ctx = MCTPSMBusContextResponse::new(SOURCE_ID);

        let header = ctx.generate_smbus_header(DEST_ID);
        let buf = header.0;

        // Destination slave address, bit 0 is always 0.
        assert_eq!(buf[0], DEST_ID << 1);
        // Command code, is always 0x0F
        assert_eq!(buf[1], MCTP_SMBUS_COMMAND_CODE);
        // Byte count, is set later
        assert_eq!(buf[2], 0);
        // Source slave address, bit 0 is always 1
        assert_eq!(buf[3], SOURCE_ID << 1 | 1);
    }

    #[test]
    fn test_generate_transport_header() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x23;

        let ctx = MCTPSMBusContextResponse::new(SOURCE_ID);

        let header = ctx.generate_transport_header(DEST_ID);
        let buf = header.0;

        // HDR version and reserved field
        assert_eq!(buf[0], HDR_VERSION);
        // Destination endpoint ID
        assert_eq!(buf[1], DEST_ID);
        // Source endpoint ID
        assert_eq!(buf[2], SOURCE_ID);
        // SOM, EOM, Pck_seq, TO and Msg_tab
        assert_eq!(buf[3], 1 << 7 | 1 << 6 | 0 << 4 | 1 << 3 | 0);
    }

    #[test]
    fn test_get_mctp_version_support() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x23;

        let ctx = MCTPSMBusContextResponse::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx.get_mctp_version_support(DEST_ID, &mut buf);

        assert_eq!(len, 17);

        // Byte count
        assert_eq!(buf[2], 14);

        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 0 << 7 | 0 << 6 | 0 << 5 | 0);

        // Command Code
        assert_eq!(buf[10], CommandCode::GetMCTPVersionSupport as u8);
        // Completion Code
        assert_eq!(buf[11], CompletionCode::Success as u8);

        // Version Entry Count
        assert_eq!(buf[12], 1);
        // Major version number
        assert_eq!(buf[13], 0xF1);
        // Major version number
        assert_eq!(buf[14], 0xF3);
        // Update version number
        assert_eq!(buf[15], 0xF1);
        // Alpha byte
        assert_eq!(buf[16], 0x00);
    }
}
