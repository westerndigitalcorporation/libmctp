//! Traits used for the MCTP implementation.
//!
//! This is an internal implementation.

use crate::base_packet::{
    MCTPMessageBody, MCTPMessageBodyHeader, MCTPTransportHeader, MessageType,
};
use crate::control_packet::CommandCode;
use crate::smbus_proto::{MCTPSMBusHeader, MCTPSMBusPacket, HDR_VERSION, MCTP_SMBUS_COMMAND_CODE};

/// The standard trait for all MCTP headers
pub(crate) trait MCTPHeader {
    /// Return the number of bytes in the header
    fn len(&self) -> usize;

    /// Check if the header is empty
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Store the header packet into a buffer and return
    /// the number of bytes stored. The return value is the same as
    /// calling `len()`.
    ///
    /// `buffer`: a mutable buffer to store the bytes from the struct.
    /// `buffer` is formated as valid MCTP data.
    fn to_raw_bytes(&self, buf: &mut [u8]) -> usize;
}

/// The standard trait for the MCTP Control Message request type
pub(crate) trait MCTPControlMessageRequest {
    fn command_code(&self) -> u8;

    /// Get the length of the request data command
    fn get_request_data_len(&self) -> usize {
        match self.command_code().into() {
            CommandCode::Reserved => 0,
            CommandCode::SetEndpointID => unimplemented!(),
            CommandCode::GetEndpointID => unimplemented!(),
            CommandCode::GetEndpointUUID => unimplemented!(),
            CommandCode::GetMCTPVersionSupport => 1,
            CommandCode::GetMessageTypeSupport => unimplemented!(),
            CommandCode::GetVendorDefinedMessageSupport => unimplemented!(),
            CommandCode::ResolveEndpointID => unimplemented!(),
            CommandCode::AllocateEndpointIDs => unimplemented!(),
            CommandCode::RoutingInformationUpdate => unimplemented!(),
            CommandCode::GetRoutingTableEntries => unimplemented!(),
            CommandCode::PrepareForEndpointDiscovery => unimplemented!(),
            CommandCode::EndpointDiscovery => unimplemented!(),
            CommandCode::DiscoveryNotify => unimplemented!(),
            CommandCode::GetNetworkID => unimplemented!(),
            CommandCode::QueryHop => unimplemented!(),
            CommandCode::ResolveUUID => unimplemented!(),
            CommandCode::QueryRateLimit => unimplemented!(),
            CommandCode::RequestTXRateLimit => unimplemented!(),
            CommandCode::UpdateRateLimit => unimplemented!(),
            CommandCode::QuerySupportedInterfaces => unimplemented!(),
            CommandCode::Unknown => unimplemented!(),
        }
    }

    /// Get the length of the response data command
    fn get_response_data_len(&self) -> usize {
        match self.command_code().into() {
            CommandCode::Reserved => 0,
            CommandCode::SetEndpointID => unimplemented!(),
            CommandCode::GetEndpointID => unimplemented!(),
            CommandCode::GetEndpointUUID => unimplemented!(),
            CommandCode::GetMCTPVersionSupport => 5,
            CommandCode::GetMessageTypeSupport => unimplemented!(),
            CommandCode::GetVendorDefinedMessageSupport => unimplemented!(),
            CommandCode::ResolveEndpointID => unimplemented!(),
            CommandCode::AllocateEndpointIDs => unimplemented!(),
            CommandCode::RoutingInformationUpdate => unimplemented!(),
            CommandCode::GetRoutingTableEntries => unimplemented!(),
            CommandCode::PrepareForEndpointDiscovery => unimplemented!(),
            CommandCode::EndpointDiscovery => unimplemented!(),
            CommandCode::DiscoveryNotify => unimplemented!(),
            CommandCode::GetNetworkID => unimplemented!(),
            CommandCode::QueryHop => unimplemented!(),
            CommandCode::ResolveUUID => unimplemented!(),
            CommandCode::QueryRateLimit => unimplemented!(),
            CommandCode::RequestTXRateLimit => unimplemented!(),
            CommandCode::UpdateRateLimit => unimplemented!(),
            CommandCode::QuerySupportedInterfaces => unimplemented!(),
            CommandCode::Unknown => unimplemented!(),
        }
    }
}

/// The standard trait for SMBus Request and Response
pub(crate) trait SMBusMCTPRequestResponse {
    /// Get the address of the device
    ///
    /// Returns the address
    fn get_address(&self) -> u8;

    /// Get the current EID of the device
    ///
    /// Returns the EID
    fn get_eid(&self) -> u8;

    /// Set the EID of the device
    ///
    /// `eid`: The new eid to use
    fn set_eid(&self, eid: u8);

    /// Generate a transport header
    fn generate_transport_header(&self, dest_addr: u8) -> MCTPTransportHeader<[u8; 4]> {
        let mut base_header: MCTPTransportHeader<[u8; 4]> = MCTPTransportHeader::new(HDR_VERSION);
        base_header.set_dest_endpoint_id(dest_addr);
        base_header.set_source_endpoint_id(self.get_address());
        base_header.set_som(true as u8);
        base_header.set_eom(true as u8);
        base_header.set_pkt_seq(0);
        base_header.set_to(true as u8);
        base_header.set_msg_tag(0);

        base_header
    }

    /// Generate a SMBus header
    fn generate_smbus_header(&self, dest_addr: u8) -> MCTPSMBusHeader<[u8; 4]> {
        let mut smbus_header: MCTPSMBusHeader<[u8; 4]> = MCTPSMBusHeader::new();
        smbus_header.set_dest_read_write(0);
        smbus_header.set_dest_slave_addr(dest_addr);
        smbus_header.set_command_code(MCTP_SMBUS_COMMAND_CODE);
        smbus_header.set_source_slave_addr(self.get_address());
        smbus_header.set_source_read_write(1);

        smbus_header
    }

    /// Store the packet bytes in the `buf`.
    fn generate_packet_bytes(
        &self,
        dest_addr: u8,
        message_header: &Option<&[u8]>,
        message_data: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        let mut smbus_header = self.generate_smbus_header(dest_addr);
        let base_header = self.generate_transport_header(dest_addr);

        let header: MCTPMessageBodyHeader<[u8; 1]> =
            MCTPMessageBodyHeader::new(false, MessageType::MCtpControl);

        let body = MCTPMessageBody::new(&header, *message_header, &message_data, None);

        let packet = MCTPSMBusPacket::new(&mut smbus_header, &base_header, &body);

        Ok(packet.to_raw_bytes(buf))
    }
}
