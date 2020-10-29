//! The SMBus specific protocol implementation.

use crate::base_packet::{
    MCTPMessageBody, MCTPMessageBodyHeader, MCTPTransportHeader, MessageType,
};
use crate::control_packet::MCTPControlMessageRequestHeader;
use crate::smbus_raw::MCTPSMBusPacket;
use crate::smbus_raw::{MCTPSMBusContextRaw, MCTPSMBusHeader};

/// The global context for MCTP SMBus operations
pub struct MCTPSMBusContext {
    raw: MCTPSMBusContextRaw,
}

impl MCTPSMBusContext {
    /// Create a new SBMust context
    ///
    /// `address`: The source address of this device
    pub fn new(address: u8) -> Self {
        Self {
            raw: MCTPSMBusContextRaw::new(address),
        }
    }

    /// Get the underlying raw protocol struct.
    /// This can be used to generate specific packets
    pub fn get_raw(&self) -> &MCTPSMBusContextRaw {
        &self.raw
    }

    /// Decode a MCTP packet
    pub fn decode_packet<'a>(&self, buf: &'a [u8]) -> Result<(MessageType, &'a [u8]), ()> {
        // buf is a MCTPSMBusPacket
        let mut smbus_header_buf: [u8; 4] = [0; 4];
        smbus_header_buf.copy_from_slice(&buf[0..4]);
        let smbus_header = MCTPSMBusHeader::new_from_buf(smbus_header_buf);

        let mut base_header_buf: [u8; 4] = [0; 4];
        base_header_buf.copy_from_slice(&buf[4..8]);
        let base_header = MCTPTransportHeader::new_from_buf(base_header_buf);

        let body_header = MCTPMessageBodyHeader::new_from_buf([buf[8]]);

        match body_header.msg_type().into() {
            MessageType::MCtpControl => {
                let mut control_message_header_buf: [u8; 2] = [0; 2];
                control_message_header_buf.copy_from_slice(&buf[9..11]);
                let body_additional_header =
                    MCTPControlMessageRequestHeader::new_from_buf(control_message_header_buf);

                let body_additional_header_buf = Some(&(buf[9..11]));
                let data = &buf[11..];

                if data.len() != body_additional_header.get_request_data_len() {
                    return Err(());
                }

                let body =
                    MCTPMessageBody::new(body_header, &body_additional_header_buf, data, None);

                let _packet = MCTPSMBusPacket::new(smbus_header, base_header, &body);

                Ok((MessageType::MCtpControl, data))
            }
            MessageType::VendorDefinedPCI => unimplemented!(),
            MessageType::VendorDefinedIANA => unimplemented!(),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod smbus_tests {
    use super::*;
    use crate::control_packet::MCTPVersionQuery;

    #[test]
    fn test_decode() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x23;

        let ctx = MCTPSMBusContext::new(SOURCE_ID);
        let mut buf: [u8; 12] = [0; 12];

        let _len = ctx.get_raw().get_mctp_version_support(
            DEST_ID,
            MCTPVersionQuery::MCTPBaseSpec,
            &mut buf,
        );

        let (msg_type, payload) = ctx.decode_packet(&buf).unwrap();

        assert_eq!(msg_type, MessageType::MCtpControl);
        assert_eq!(payload.len(), 1);
        assert_eq!(payload[0], MCTPVersionQuery::MCTPBaseSpec as u8);
    }
}
