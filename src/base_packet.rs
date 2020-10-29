//! This defines the structs and helpers for the standard packet types.
//!
//! This provides the low level structs for creating MCTP packets.
//! This is generally only used by libMCTP.

use crate::mctp_traits::MCTPHeader;

/// The Message Type of the MCTP packet
#[derive(Debug, PartialEq)]
pub enum MessageType {
    /// A control message
    MCtpControl = 0x00,
    /// Message type used to support VDMs where the vendor is identified using
    /// a PCI-based vendor ID.
    VendorDefinedPCI = 0x7E,
    /// Message type used to support VDMs where the vendor is identified using
    /// an IANA-based vendor ID.
    VendorDefinedIANA = 0x7F,
    /// Internal use
    Invalid = 0xFF,
}

impl From<u8> for MessageType {
    fn from(num: u8) -> MessageType {
        match num {
            0x00 => MessageType::MCtpControl,
            0x7E => MessageType::VendorDefinedPCI,
            0x7F => MessageType::VendorDefinedIANA,
            _ => MessageType::Invalid,
        }
    }
}

bitfield! {
    /// The MCTP Transport Header.
    pub struct MCTPTransportHeader(MSB0 [u8]);
    u8;
    rsvd, _ : 3, 0;
    /// Header version
    pub hdr_version, set_hdr_version: 7, 4;
    /// Destination Endpoint ID
    pub dest_endpoint_id, set_dest_endpoint_id: 15, 8;
    /// Source Endpoint ID
    pub source_endpoint_id, set_source_endpoint_id: 23, 16;
    /// Start of Message
    pub som, set_som: 24, 24;
    /// End of Message
    pub eom, set_eom: 25, 25;
    /// Packet Sequence Number
    pub pkt_seq, set_pkt_seq: 27, 26;
    /// Tag Owner
    pub to, set_to: 28, 28;
    /// Message Tag
    pub msg_tag, set_msg_tag: 31, 29;
}

impl MCTPTransportHeader<[u8; 4]> {
    /// Create a new MCTPTransportHeader.
    ///
    /// `header`: The transport layer specific header version.
    pub fn new(header: u8) -> Self {
        let buf = [0; 4];
        let mut tran_header = MCTPTransportHeader(buf);

        tran_header.set_hdr_version(header);

        tran_header
    }

    /// Create a new MCTPTransportHeader from an existing buffer.
    pub fn new_from_buf(buf: [u8; 4]) -> Self {
        MCTPTransportHeader(buf)
    }
}

bitfield! {
    /// The MCTP Transport Body Header.
    pub struct MCTPMessageBodyHeader(MSB0 [u8]);
    u8;
    ic, set_ic: 0, 0;
    /// The message type
    pub msg_type, set_msg_type: 7, 1;
}

impl MCTPMessageBodyHeader<[u8; 1]> {
    /// Create a new MCTPMessageBodyHeader.
    ///
    /// `ic`: (MCTP integrity check bit) Indicates whether the MCTP message
    /// is covered by an overall MCTP message payload integrity check.
    /// `msg_type`: Defines the type of payload contained in the message
    /// data portion of the MCTP message.
    pub fn new(ic: bool, msg_type: MessageType) -> Self {
        let buf = [0; 1];
        let mut body_header = MCTPMessageBodyHeader(buf);

        body_header.set_ic(ic as u8);
        body_header.set_msg_type(msg_type as u8);

        body_header
    }

    /// Create a new MCTPMessageBodyHeader from an existing buffer.
    pub fn new_from_buf(buf: [u8; 1]) -> Self {
        MCTPMessageBodyHeader(buf)
    }
}

/// The MCTP Message Body, this is included inside the high level packet.
pub struct MCTPMessageBody<'a> {
    header: MCTPMessageBodyHeader<[u8; 1]>,
    additional_header: &'a Option<&'a [u8]>,
    data: &'a [u8],
    mic: Option<&'a [u8]>,
}

impl<'a> MCTPMessageBody<'a> {
    /// Creates a new MCTPMessageBody.
    pub fn new(
        header: MCTPMessageBodyHeader<[u8; 1]>,
        additional_header: &'a Option<&'a [u8]>,
        data: &'a [u8],
        mic: Option<&'a [u8]>,
    ) -> Self {
        Self {
            header,
            additional_header,
            data,
            mic,
        }
    }
}

impl<'a> MCTPHeader for MCTPMessageBody<'a> {
    /// Return the number of bytes used by the packet.
    fn len(&self) -> usize {
        let mut offset = 0;

        offset += 1;

        if let Some(head_buf) = &self.additional_header {
            offset += head_buf.len();
        }

        offset += self.data.len();

        if let Some(mic_buf) = &self.mic {
            offset += mic_buf.len();
        }

        offset
    }

    /// Store the MCTPMessageBody packet into a buffer.
    fn to_raw_bytes(&self, buf: &mut [u8]) -> usize {
        let mut offset = 0;

        buf[offset..(offset + 1)].copy_from_slice(&self.header.0);
        offset += 1;

        if let Some(head_buf) = &self.additional_header {
            buf[offset..(offset + head_buf.len())].copy_from_slice(head_buf);
            offset += head_buf.len();
        }

        buf[offset..(offset + self.data.len())].copy_from_slice(self.data);
        offset += self.data.len();

        if let Some(mic_buf) = &self.mic {
            buf[offset..(offset + mic_buf.len())].copy_from_slice(mic_buf);
            offset += mic_buf.len();
        }

        offset
    }
}

#[cfg(test)]
mod smbus_tests {
    use super::*;

    #[test]
    fn test_transport_header() {
        const VERSION: u8 = 0b001;
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x23;

        let mut tran_header = MCTPTransportHeader::new(VERSION);
        tran_header.set_dest_endpoint_id(DEST_ID);
        tran_header.set_source_endpoint_id(SOURCE_ID);
        tran_header.set_som(false as u8);

        tran_header.set_eom(false as u8);

        tran_header.set_pkt_seq(0);
        tran_header.set_to(false as u8);
        tran_header.set_msg_tag(0);

        assert_eq!(tran_header.hdr_version(), VERSION);
        assert_eq!(tran_header.dest_endpoint_id(), DEST_ID);
        assert_eq!(tran_header.source_endpoint_id(), SOURCE_ID);
    }

    #[test]
    fn test_message_body_header() {
        let body_header = MCTPMessageBodyHeader::new(false, MessageType::MCtpControl);

        assert_eq!(body_header.ic(), 0);
        assert_eq!(body_header.msg_type(), MessageType::MCtpControl as u8);
    }

    #[test]
    fn test_message_body() {
        let header: MCTPMessageBodyHeader<[u8; 1]> =
            MCTPMessageBodyHeader::new(false, MessageType::VendorDefinedPCI);
        let additional_header = None;
        let data: [u8; 4] = [0x11; 4];
        let mic = None;

        let body = MCTPMessageBody::new(header, &additional_header, &data, mic);
        let mut buf: [u8; 32] = [0; 32];

        let len = body.to_raw_bytes(&mut buf);

        assert_eq!(len, 5);

        assert_eq!(buf[0], MessageType::VendorDefinedPCI as u8);
    }
}
