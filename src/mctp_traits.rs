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

    /// Convert the header to raw bytes
    fn to_raw_bytes(&self, buf: &mut [u8]) -> usize;
}

pub(crate) trait MCTPControlMessageRequest {
    fn command_code(&self) -> u8;

    /// Get the length of the request data command
    fn get_request_data_len(&self) -> usize {
        match self.command_code().into() {
            CommandCode::Reserved => unimplemented!(),
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
            CommandCode::Reserved => unimplemented!(),
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
