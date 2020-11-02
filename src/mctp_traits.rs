//! Traits used for the MCTP implementation.
//!
//! This is an internal implementation.

use crate::control_packet::CommandCode;

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
