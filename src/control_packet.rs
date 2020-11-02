//! This describes the MCTP Control Message headers and protocols.
//!
//! The control packet is described in DSP0236, section 11.

use crate::mctp_traits::MCTPControlMessageRequest;

bitfield! {
    /// This is the header for a Control Message, without the completion code.
    pub struct MCTPControlMessageHeader(MSB0 [u8]);
    u8;
    /// Is the packet a request?
    pub rq, set_rq : 0, 0;
    /// Is this packet a datagram?
    d, set_d: 1, 1;
    rsvd, _: 2, 2;
    instance_id, set_instance_id: 7, 3;
    /// The command code of the packet
    command_code, set_command_code: 15, 8;
}

/// A list of supported Command Codes
pub enum CommandCode {
    /// Reserved
    Reserved = 0x00,
    /// Assigns an EID to the endpoint at the given physical address.
    SetEndpointID = 0x01,
    /// Returns the EID presently assigned to an endpoint.
    GetEndpointID = 0x02,
    /// Retrieves a per-device unique UUID associated with the endpoint.
    GetEndpointUUID = 0x03,
    /// Lists which versions of the MCTP control protocol are supported on an
    /// endpoint.
    GetMCTPVersionSupport = 0x04,
    /// Lists the message types that an endpoint supports.
    GetMessageTypeSupport = 0x05,
    /// Used to discover an MCTP endpoint’s vendor-specific MCTP extensions
    /// and capabilities.
    GetVendorDefinedMessageSupport = 0x06,
    /// Used to get the physical address associated with a given EID.
    ResolveEndpointID = 0x07,
    /// Used by the bus owner to allocate a pool of EIDs to an MCTP bridge
    AllocateEndpointIDs = 0x08,
    /// Used by the bus owner to extend or update the routing information that
    /// is maintained by an MCTP bridge
    RoutingInformationUpdate = 0x09,
    /// Used to request an MCTP bridge to return data corresponding to its
    /// present routing table entries
    GetRoutingTableEntries = 0x0A,
    /// Used to direct endpoints to clear their “discovered”flags to enable
    /// them to respond to the Endpoint Discovery command
    PrepareForEndpointDiscovery = 0x0B,
    /// Used to discover MCTP-capable devices on a bus, provided that another
    /// discovery mechanism is not defined for the particular physical medium
    EndpointDiscovery = 0x0C,
    /// Used to notify the bus owner that an MCTP device has become available
    /// on the bus
    DiscoveryNotify = 0x0D,
    /// Used to get the MCTP networkID
    GetNetworkID = 0x0E,
    /// Used to discover what bridges, if any, are in the path to a given
    /// target endpoint and what transmission unit sizes the bridges will pass
    /// for a given message type when routing to the target endpoint
    QueryHop = 0x0F,
    /// Used by endpoints to find another endpoint matching an endpoint that
    /// uses a specific UUID
    ResolveUUID = 0x10,
    /// Used to discover the data rate limit settings of the given target
    /// for incoming messages
    QueryRateLimit = 0x11,
    /// Used to request the allowed transmit data rate limit for the given
    /// endpoint for outgoing messages
    RequestTXRateLimit = 0x12,
    /// Used to update the receiving side on change to the transmit data
    /// rate which was not requested by the receiver
    UpdateRateLimit = 0x13,
    /// Used to discover the existing device MCTP interfaces
    QuerySupportedInterfaces = 0x14,
    /// Not supported
    Unknown = 0xFF,
}

impl From<u8> for CommandCode {
    fn from(num: u8) -> CommandCode {
        match num {
            0x00 => CommandCode::Reserved,
            0x01 => CommandCode::SetEndpointID,
            0x02 => CommandCode::GetEndpointID,
            0x03 => CommandCode::GetEndpointUUID,
            0x04 => CommandCode::GetMCTPVersionSupport,
            0x05 => CommandCode::GetMessageTypeSupport,
            0x06 => CommandCode::GetVendorDefinedMessageSupport,
            0x07 => CommandCode::ResolveEndpointID,
            0x08 => CommandCode::AllocateEndpointIDs,
            0x09 => CommandCode::RoutingInformationUpdate,
            0x0A => CommandCode::GetRoutingTableEntries,
            0x0B => CommandCode::PrepareForEndpointDiscovery,
            0x0C => CommandCode::EndpointDiscovery,
            0x0D => CommandCode::DiscoveryNotify,
            0x0E => CommandCode::GetNetworkID,
            0x0F => CommandCode::QueryHop,
            0x10 => CommandCode::ResolveUUID,
            0x11 => CommandCode::QueryRateLimit,
            0x12 => CommandCode::RequestTXRateLimit,
            0x13 => CommandCode::UpdateRateLimit,
            0x14 => CommandCode::QuerySupportedInterfaces,
            _ => CommandCode::Unknown,
        }
    }
}

/// This field is only present in Response messages. This field contains a
/// value that indicates whether the response completed normally. If the
/// command did not complete normally, the value can provide additional
/// information regarding the error condition. The values for completion
/// codes are specified in Table 13.
#[derive(Debug, PartialEq)]
pub enum CompletionCode {
    /// The Request was accepted and completed normally
    Success = 0x00,
    /// This is a generic failure message. (It should not be used when a
    /// more specific result code applies.)
    Error = 0x01,
    /// The packet payload contained invalid data or an illegal parameter
    /// value.
    ErrorInvalidData = 0x02,
    /// The message length was invalid. (The Message body was larger or
    /// smaller than expected for the particular request.)
    ErrorInvalidLength = 0x03,
    /// The Receiver is in a transient state where it is not ready to
    /// receive the corresponding message
    ErrorNotReady = 0x04,
    /// The command field in the control type of the received message
    /// is unspecified or not supported on this endpoint. This completion
    /// code shall be returned for any unsupported command values received
    /// in MCTP control Request messages.
    ErrorUnsupportedCmd = 0x05,
}

impl From<u8> for CompletionCode {
    fn from(num: u8) -> CompletionCode {
        match num {
            0x00 => CompletionCode::Success,
            0x01 => CompletionCode::Error,
            0x02 => CompletionCode::ErrorInvalidData,
            0x03 => CompletionCode::ErrorInvalidLength,
            0x04 => CompletionCode::ErrorNotReady,
            0x05 => CompletionCode::ErrorUnsupportedCmd,
            _ => unreachable!(),
        }
    }
}

/// The type of version query when calling GetMCTPVersionSupport
pub enum MCTPVersionQuery {
    /// return MCTP base specification version information
    MCTPBaseSpec = 0xFF,
    /// return MCTP control protocol message version information
    MCTPControlProcMessage = 0x00,
    /// return version of DSP0241
    DSP0241 = 0x01,
    /// return version of DSP0261
    DSP0261 = 0x02,
    /// return version of DSP0261
    DSP0261_2 = 0x03,
}

impl MCTPControlMessageHeader<[u8; 2]> {
    /// Create a new MCTPControlMessageHeader.
    ///
    /// `request`: Request bit. This bit is used to help differentiate between
    /// MCTP control Request messages and other message classes.Refer to 11.5.
    /// `datagram`: This bit is used to indicate whether the Instance
    /// ID field is being used for tracking and matching requests and
    /// responses, or is just being used to identify a retransmitted message.
    /// Refer to 11.5.
    /// `instance_id`: The Instance ID field is used to identify new instances
    /// of an MCTP control Request or Datagram to differentiate new requests or
    /// datagrams that are sent to a given message terminus from retried
    /// messages that are sent to the same message terminus. The Instance ID
    /// field is also used to match up a particular instance of an MCTP
    /// Response message with the corresponding instance of an MCTP Request
    /// message.
    /// `command_code`: For Request messages, this field is a command code
    /// indicating the type of MCTP operation the packet is requesting. Command
    /// code values are defined in Table 12. The format and definition of
    /// request and response parameters for the commands is given in Clause 12.
    /// The Command Code that is sent in a Request shall be returned in the
    /// corresponding Response.
    pub fn new(request: bool, datagram: bool, instance_id: u8, command_code: CommandCode) -> Self {
        let buf = [0; 2];
        let mut con_header = MCTPControlMessageHeader(buf);

        con_header.set_rq(request as u8);
        con_header.set_d(datagram as u8);
        con_header.set_instance_id(instance_id);
        con_header.set_command_code(command_code as u8);

        con_header
    }

    /// Create a new `MCTPControlMessageHeader` from an existing buffer.
    ///
    /// `buffer`: The existing buffer for the `MCTPControlMessageHeader`
    /// No checks are performed on the `buffer`.
    pub fn new_from_buf(buf: [u8; 2]) -> Self {
        MCTPControlMessageHeader(buf)
    }
}

impl MCTPControlMessageRequest for MCTPControlMessageHeader<[u8; 2]> {
    /// Get the command code from a `MCTPControlMessageHeader`.
    fn command_code(&self) -> u8 {
        self.command_code()
    }
}
