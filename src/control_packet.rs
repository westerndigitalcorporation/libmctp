//! This describes the MCTP Control Message headers and protocols.

bitfield! {
    /// This is the header Control Message without the completion code. This
    /// is used for MCTP Control Message requests.
    pub struct MCTPControlMessageRequestHeader(MSB0 [u8]);
    u8;
    rq, set_rq : 0, 0;
    d, set_d: 1, 1;
    rsvd, _: 2, 2;
    instance_id, set_instance_id: 7, 3;
    command_code, set_command_code: 15, 8;
}

impl MCTPControlMessageRequestHeader<[u8; 2]> {
    /// Create a new MCTPControlMessageRequestHeader.
    ///
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
    pub fn new(datagram: bool, instance_id: u8, command_code: CommandCode) -> Self {
        let buf = [0; 2];
        let mut con_header = MCTPControlMessageRequestHeader(buf);

        con_header.set_rq(1);
        con_header.set_d(datagram as u8);
        con_header.set_instance_id(instance_id);
        con_header.set_command_code(command_code as u8);

        con_header
    }
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
    /// Lists which versions of the MCTP control protocol are supported on an endpoint.
    GetMCTPVersionSupport = 0x04,
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
