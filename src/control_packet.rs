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

impl MCTPControlMessageRequestHeader<[u8; 4]> {
    /// Create a new MCTPControlMessageRequestHeader.
    ///
    /// `request`: This bit is used to help differentiate between MCTP
    /// control Request messages and other message classes. Refer to 11.5.
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
    pub fn new(request: bool, datagram: bool, instance_id: u8, command_code: u8) -> Self {
        let buf = [0; 4];
        let mut con_header = MCTPControlMessageRequestHeader(buf);

        con_header.set_rq(request as u8);
        con_header.set_d(datagram as u8);
        con_header.set_instance_id(instance_id);
        con_header.set_command_code(command_code);

        con_header
    }
}
