//! The SMBus specific protocol implementation.
//!
//! This should be used when you want to communicate via MCTP over SMBus/I2C.
//!
//! In order to use this you first need to create the main context struct. Then
//! the `get_request()`/`get_response()` functions can be used to issue raw
//! commands.
//!
//! The libmctp library will not send the packets, instead it will create a
//! buffer containing the data to be sent. This allows you to use your own
//! SMBus/I2C implementation.
//!
//! ## Generate a MCTP request
//! ```rust
//!     use libmctp::control_packet::MCTPVersionQuery;
//!     use libmctp::smbus::{MCTPSMBusContext, VendorIDFormat};
//!
//!     // The address of this device
//!     const MY_ID: u8 = 0x23;
//!     // Support vendor defined protocol 0x7E
//!     let msg_types: [u8; 1] = [0x7E];
//!     // Specify a PCI vendor ID that we support
//!     let vendor_ids = [VendorIDFormat {
//!         // PCI Vendor ID
//!         format: 0x00,
//!         // PCI VID
//!         data: 0x1414,
//!         // Extra data
//!         numeric_value: 4,
//!     }];
//!     let ctx = MCTPSMBusContext::new(MY_ID, &msg_types, &vendor_ids);
//!
//!     let mut buf: [u8; 32] = [0; 32];
//!
//!     const DEST_ID: u8 = 0x34;
//!     let len = ctx.get_request().get_mctp_version_support(
//!         DEST_ID,
//!         MCTPVersionQuery::MCTPBaseSpec,
//!         &mut buf,
//!     );
//!
//!     // Send the request buf of length len via SMBus
//! ```
//!
//! ## Generate a MCTP response
//! ```rust
//!     use libmctp::control_packet::{CompletionCode, MCTPVersionQuery};
//!     use libmctp::smbus::{MCTPSMBusContext, VendorIDFormat};
//!
//!     // The address of this device
//!     const MY_ID: u8 = 0x23;
//!     // Support vendor defined protocol 0x7E
//!     let msg_types: [u8; 1] = [0x7E];
//!     // Specify a PCI vendor ID that we support
//!     let vendor_ids = [VendorIDFormat {
//!         // PCI Vendor ID
//!         format: 0x00,
//!         // PCI VID
//!         data: 0x1414,
//!         // Extra data
//!         numeric_value: 4,
//!     }];
//!     let ctx = MCTPSMBusContext::new(MY_ID, &msg_types, &vendor_ids);
//!
//!     let mut buf: [u8; 32] = [0; 32];
//!
//!     const DEST_ID: u8 = 0x34;
//!     let len = ctx.get_response().get_mctp_version_support(
//!         CompletionCode::Success,
//!         DEST_ID,
//!         &mut buf,
//!     );
//!
//!     // Send the response buf of length len via SMBus
//! ```
//!
//! ## Decode a packet received
//! ```rust
//!     use libmctp::control_packet::MCTPVersionQuery;
//!     use libmctp::smbus::{MCTPSMBusContext, VendorIDFormat};
//!
//!     // The address of this device
//!     const MY_ID: u8 = 0x23;
//!     // Support vendor defined protocol 0x7E
//!     let msg_types: [u8; 1] = [0x7E];
//!     // Specify a PCI vendor ID that we support
//!     let vendor_ids = [VendorIDFormat {
//!         // PCI Vendor ID
//!         format: 0x00,
//!         // PCI VID
//!         data: 0x1414,
//!         // Extra data
//!         numeric_value: 4,
//!     }];
//!     let ctx = MCTPSMBusContext::new(MY_ID, &msg_types, &vendor_ids);
//!     let mut buf: [u8; 32] = [0; 32];
//!
//!     // Receive data into buf from SMBus
//!
//!     let ret = ctx.decode_packet(&buf);
//!
//!     // Match and decode the returned value
//! ```
//!
//! ## Process a request to generate a response
//! ```rust
//!     use libmctp::control_packet::MCTPVersionQuery;
//!     use libmctp::smbus::{MCTPSMBusContext, VendorIDFormat};
//!
//!     // The address of this device
//!     const MY_ID: u8 = 0x23;
//!     // Support vendor defined protocol 0x7E
//!     let msg_types: [u8; 1] = [0x7E];
//!     // Specify a PCI vendor ID that we support
//!     let vendor_ids = [VendorIDFormat {
//!         // PCI Vendor ID
//!         format: 0x00,
//!         // PCI VID
//!         data: 0x1414,
//!         // Extra data
//!         numeric_value: 4,
//!     }];
//!     let ctx = MCTPSMBusContext::new(MY_ID, &msg_types, &vendor_ids);
//!     let mut buf_request: [u8; 32] = [0; 32];
//!     let mut buf_response: [u8; 32] = [0; 32];
//!
//!     // Receive data into buf_request from SMBus
//!
//!     let ret = ctx.process_packet(&buf_request, &mut buf_response);
//!
//!     // Match and decode the returned value
//! ```

use crate::base_packet::{
    MCTPMessageBody, MCTPMessageBodyHeader, MCTPTransportHeader, MessageType,
};
use crate::control_packet::{
    CommandCode, CompletionCode, MCTPControlMessageHeader, MCTPGetEndpointIDEndpointIDType,
    MCTPGetEndpointIDEndpointType, MCTPSetEndpointIDAllocationStatus,
    MCTPSetEndpointIDAssignmentStatus, MCTPSetEndpointIDOperations,
};
use crate::errors::{ControlMessageError, DecodeError};
use crate::mctp_traits::{MCTPControlMessageRequest, SMBusMCTPRequestResponse};
use crate::smbus_proto::{MCTPSMBusHeader, MCTPSMBusPacket, HDR_VERSION};
use crate::smbus_request::MCTPSMBusContextRequest;
use crate::smbus_response::MCTPSMBusContextResponse;
use core::cell::Cell;

/// The returned data for SMBus headers
type SMBusHeaders = (
    MCTPSMBusHeader<[u8; 4]>,
    MCTPTransportHeader<[u8; 4]>,
    MCTPMessageBodyHeader<[u8; 1]>,
);

/// The returned data for decoding control packets
type ControlDecodedPacketData<'a> = (MessageType, &'a [u8]);

/// The returned data for for raw control packets
type ControlRawPacketData<'a, 'b> = (
    MCTPControlMessageHeader<[u8; 2]>,
    Option<CompletionCode>,
    MCTPMessageBody<'a, 'b>,
);

/// The Vendor ID Format as described in table 21
pub struct VendorIDFormat {
    /// The Vendor ID Format
    ///  * PCI Vendor ID: 0
    ///  * IANA Enterprise Number: 1
    pub format: u8,
    /// The vendor ID data, either 2 or 4 bytes
    pub data: u32,
    /// An extra 2 bytes
    pub numeric_value: u16,
}

/// The global context for MCTP SMBus operations
pub struct MCTPSMBusContext<'m> {
    request: MCTPSMBusContextRequest,
    response: MCTPSMBusContextResponse,
    uuid: [u8; 16],
    msg_types: &'m [u8],
    vendor_id_selector: Cell<u8>,
    vendor_ids: &'m [VendorIDFormat],
}

impl<'m> MCTPSMBusContext<'m> {
    /// Create a new SBMust context
    ///
    /// `address`: The source address of this device.
    pub fn new(address: u8, msg_types: &'m [u8], vendor_ids: &'m [VendorIDFormat]) -> Self {
        Self {
            request: MCTPSMBusContextRequest::new(address),
            response: MCTPSMBusContextResponse::new(address),
            uuid: [0; 16],
            msg_types,
            vendor_id_selector: Cell::new(0),
            vendor_ids,
        }
    }

    /// Get the underlying request protocol struct.
    /// This can be used to manually generate specific packets
    pub fn get_request(&self) -> &MCTPSMBusContextRequest {
        &self.request
    }

    /// Get the underlying response protocol struct.
    /// This can be used to manually generate specific packets
    pub fn get_response(&self) -> &MCTPSMBusContextResponse {
        &self.response
    }

    /// Set the Unique Identifier for this device
    pub fn set_uuid(&mut self, uuid: &[u8]) {
        self.uuid.copy_from_slice(uuid)
    }

    /// Get the SMBus headers from a packet
    ///
    /// `packet`: A buffer of the packet to get the headers from.
    fn get_smbus_headers(&self, packet: &[u8]) -> Result<SMBusHeaders, (MessageType, DecodeError)> {
        // packet is a MCTPSMBusPacket
        let mut smbus_header_buf: [u8; 4] = [0; 4];
        smbus_header_buf.copy_from_slice(&packet[0..4]);
        let smbus_header = MCTPSMBusHeader::new_from_buf(smbus_header_buf);

        let mut base_header_buf: [u8; 4] = [0; 4];
        base_header_buf.copy_from_slice(&packet[4..8]);
        let base_header = match MCTPTransportHeader::new_from_buf(base_header_buf, HDR_VERSION) {
            Ok(header) => header,
            Err(()) => {
                return Err((MessageType::Invalid, DecodeError::Unknown));
            }
        };

        let body_header = match MCTPMessageBodyHeader::new_from_buf([packet[8]]) {
            Ok(header) => header,
            Err(()) => {
                return Err((MessageType::Invalid, DecodeError::Unknown));
            }
        };

        Ok((smbus_header, base_header, body_header))
    }

    /// Decodes a MCTP packet.
    ///
    /// `packet`: A buffer of the packet to get the headers from.
    ///
    /// On success returns the `MessageType` and a reference into `packet` where
    /// the payload starts.
    /// On error returned the `MessageType` and a `DecodeError`.
    pub fn decode_packet<'a>(
        &self,
        packet: &'a [u8],
    ) -> Result<ControlDecodedPacketData<'a>, (MessageType, DecodeError)> {
        let (smbus_header, base_header, body_header) = self.get_smbus_headers(packet)?;

        match body_header.msg_type().into() {
            MessageType::MCtpControl => {
                self.decode_mctp_control(&smbus_header, &base_header, &body_header, &packet[9..])
            }
            MessageType::VendorDefinedPCI => unimplemented!(),
            MessageType::VendorDefinedIANA => unimplemented!(),
            _ => Err((MessageType::Invalid, DecodeError::Unknown)),
        }
    }

    /// Get the MCTP control packet
    fn get_mctp_control_packet<'a, 'b>(
        &self,
        _smbus_header: &MCTPSMBusHeader<[u8; 4]>,
        _base_header: &MCTPTransportHeader<[u8; 4]>,
        body_header: &'b MCTPMessageBodyHeader<[u8; 1]>,
        packet: &'a [u8],
    ) -> Result<ControlRawPacketData<'a, 'b>, (MessageType, DecodeError)> {
        // Decode the header
        let mut control_message_header_buf: [u8; 2] = [0; 2];
        control_message_header_buf.copy_from_slice(&packet[0..2]);
        let control_message_header =
            MCTPControlMessageHeader::new_from_buf(control_message_header_buf);

        let (payload_offset, compl_comm, body_additional_header_len) =
            match control_message_header.rq() {
                1 => {
                    // Request
                    (2, None, control_message_header.get_request_data_len())
                }
                0 => {
                    // Response
                    if packet[2] != CompletionCode::Success as u8 {
                        return Err((
                            MessageType::MCtpControl,
                            DecodeError::ControlMessage(
                                ControlMessageError::UnsuccessfulCompletionCode(packet[2].into()),
                            ),
                        ));
                    }
                    (
                        3,
                        Some(packet[2].into()),
                        control_message_header.get_response_data_len(),
                    )
                }
                _ => {
                    return Err((
                        MessageType::MCtpControl,
                        DecodeError::ControlMessage(ControlMessageError::InvalidControlHeader),
                    ));
                }
            };

        let data = &packet[payload_offset..];

        if data.len() != body_additional_header_len {
            return Err((
                MessageType::MCtpControl,
                DecodeError::ControlMessage(ControlMessageError::InvalidRequestDataLength),
            ));
        }

        Ok((
            control_message_header,
            compl_comm,
            MCTPMessageBody::new(body_header, Some(&packet[0..payload_offset]), data, None),
        ))
    }

    /// Decodes a MCTP request packet
    fn decode_mctp_control<'a, 'b>(
        &self,
        smbus_header: &MCTPSMBusHeader<[u8; 4]>,
        base_header: &MCTPTransportHeader<[u8; 4]>,
        body_header: &'b MCTPMessageBodyHeader<[u8; 1]>,
        packet: &'a [u8],
    ) -> Result<ControlDecodedPacketData<'a>, (MessageType, DecodeError)> {
        let (_header, _compl_com, body) =
            self.get_mctp_control_packet(smbus_header, base_header, body_header, packet)?;
        Ok((MessageType::MCtpControl, body.data))
    }

    /// This function first decodes the packet supplied in the `packet` argument.
    /// This is done using the `decode_packet()` function.
    /// If this packet is a request then the `response_buf` is populated with
    /// a response to the request.
    ///
    /// `packet`: A buffer of the packet to get the headers from.
    ///
    /// On success the first two arguments are the same as
    /// the return from the `decode_packet()` function. The third argument is
    /// an option. If `None` then `response_buf` wasn't changed because the
    /// `packet` was not a request. If `Some` it contains the length of the
    /// data written in the `response_buf`.
    pub fn process_packet<'a, 'b>(
        &self,
        packet: &'a [u8],
        response_buf: &'b mut [u8],
    ) -> Result<(ControlDecodedPacketData<'a>, Option<usize>), (MessageType, DecodeError)> {
        let (msg_type, payload) = self.decode_packet(packet)?;

        match msg_type {
            MessageType::MCtpControl => {
                let (mut smbus_header, base_header, body_header) =
                    self.get_smbus_headers(packet)?;

                let (header, compl_com, body) = self.get_mctp_control_packet(
                    &smbus_header,
                    &base_header,
                    &body_header,
                    &packet[9..],
                )?;

                let _packet = MCTPSMBusPacket::new(&mut smbus_header, &base_header, &body);

                if compl_com.is_none() {
                    let len;

                    match header.command_code().into() {
                        CommandCode::Reserved => unreachable!(),
                        CommandCode::SetEndpointID => {
                            if payload[0] == MCTPSetEndpointIDOperations::SetEID as u8
                                || payload[0] == MCTPSetEndpointIDOperations::ForceEID as u8
                            {
                                self.get_response().set_eid(payload[1]);
                                self.get_request().set_eid(payload[1]);
                                len = self
                                    .get_response()
                                    .set_endpoint_id(
                                        CompletionCode::Success,
                                        base_header.source_endpoint_id(),
                                        MCTPSetEndpointIDAssignmentStatus::Accpeted,
                                        MCTPSetEndpointIDAllocationStatus::NoIDPool,
                                        response_buf,
                                    )
                                    .unwrap();
                            } else if payload[0] == MCTPSetEndpointIDOperations::ResetEID as u8 {
                                unimplemented!()
                            } else if payload[0]
                                == MCTPSetEndpointIDOperations::SetDiscoveredFlag as u8
                            {
                                len = self
                                    .get_response()
                                    .set_endpoint_id(
                                        CompletionCode::ErrorInvalidData,
                                        base_header.source_endpoint_id(),
                                        MCTPSetEndpointIDAssignmentStatus::Accpeted,
                                        MCTPSetEndpointIDAllocationStatus::NoIDPool,
                                        response_buf,
                                    )
                                    .unwrap();
                            } else {
                                unreachable!()
                            }
                        }
                        CommandCode::GetEndpointID => {
                            len = self
                                .get_response()
                                .get_endpoint_id(
                                    CompletionCode::Success,
                                    base_header.source_endpoint_id(),
                                    MCTPGetEndpointIDEndpointType::Simple,
                                    MCTPGetEndpointIDEndpointIDType::DynamicEID,
                                    false,
                                    response_buf,
                                )
                                .unwrap();
                        }
                        CommandCode::GetEndpointUUID => {
                            len = self
                                .get_response()
                                .get_endpoint_uuid(
                                    CompletionCode::Success,
                                    base_header.source_endpoint_id(),
                                    &self.uuid,
                                    response_buf,
                                )
                                .unwrap();
                        }
                        CommandCode::GetMCTPVersionSupport => {
                            len = self
                                .get_response()
                                .get_mctp_version_support(
                                    CompletionCode::Success,
                                    base_header.source_endpoint_id(),
                                    response_buf,
                                )
                                .unwrap();
                        }
                        CommandCode::GetMessageTypeSupport => {
                            len = self
                                .get_response()
                                .get_message_type_suport(
                                    CompletionCode::Success,
                                    base_header.source_endpoint_id(),
                                    &self.msg_types,
                                    response_buf,
                                )
                                .unwrap();
                        }
                        CommandCode::GetVendorDefinedMessageSupport => {
                            if (payload[0] + 1) == self.vendor_ids.len() as u8 {
                                // Set the Vendor ID Set Selector as the end
                                self.vendor_id_selector.set(0xFF);
                            } else {
                                // Set the Vendor ID Set Selector from the request
                                self.vendor_id_selector.set(payload[0] + 1);
                            }

                            let vendor_id = &self.vendor_ids[payload[0] as usize];
                            if vendor_id.format == 0 {
                                let vendor_data = [
                                    vendor_id.format,
                                    (vendor_id.data >> 8) as u8,
                                    vendor_id.data as u8,
                                    (vendor_id.numeric_value >> 8) as u8,
                                    vendor_id.numeric_value as u8,
                                ];

                                len = self
                                    .get_response()
                                    .get_vendor_defined_message_support(
                                        CompletionCode::Success,
                                        base_header.source_endpoint_id(),
                                        self.vendor_id_selector.get(),
                                        &vendor_data,
                                        response_buf,
                                    )
                                    .unwrap();
                            } else if vendor_id.format == 1 {
                                let vendor_data = [
                                    vendor_id.format,
                                    (vendor_id.data >> 24) as u8,
                                    (vendor_id.data >> 16) as u8,
                                    (vendor_id.data >> 8) as u8,
                                    vendor_id.data as u8,
                                    (vendor_id.numeric_value >> 8) as u8,
                                    vendor_id.numeric_value as u8,
                                ];

                                len = self
                                    .get_response()
                                    .get_vendor_defined_message_support(
                                        CompletionCode::Success,
                                        base_header.source_endpoint_id(),
                                        self.vendor_id_selector.get(),
                                        &vendor_data,
                                        response_buf,
                                    )
                                    .unwrap();
                            } else {
                                unreachable!()
                            };
                        }
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
                        _ => unimplemented!(),
                    }

                    return Ok(((msg_type, payload), Some(len)));
                }

                Ok(((msg_type, payload), None))
            }
            MessageType::VendorDefinedPCI => {
                // Vendor defined, we don't know what to do
                Ok(((msg_type, payload), None))
            }
            MessageType::VendorDefinedIANA => {
                // Vendor defined, we don't know what to do
                Ok(((msg_type, payload), None))
            }
            _ => Err((MessageType::Invalid, DecodeError::Unknown)),
        }
    }
}

#[cfg(test)]
mod version_supported_tests {
    use super::*;
    use crate::control_packet::MCTPVersionQuery;

    #[test]
    fn test_decode_request() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x34;

        let msg_types: [u8; 0] = [0; 0];
        let vendor_ids = [VendorIDFormat {
            // PCI Vendor ID
            format: 0x00,
            // PCI VID
            data: 0x1234,
            // Extra data
            numeric_value: 0xAB,
        }];

        let ctx = MCTPSMBusContext::new(SOURCE_ID, &msg_types, &vendor_ids);
        let mut buf: [u8; 12] = [0; 12];

        let _len = ctx.get_request().get_mctp_version_support(
            DEST_ID,
            MCTPVersionQuery::MCTPBaseSpec,
            &mut buf,
        );

        let (msg_type, payload) = ctx.decode_packet(&buf).unwrap();

        assert_eq!(msg_type, MessageType::MCtpControl);
        assert_eq!(payload.len(), 1);
        assert_eq!(payload[0], MCTPVersionQuery::MCTPBaseSpec as u8);
    }

    #[test]
    fn test_decode_response() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x23;

        let msg_types: [u8; 0] = [0; 0];
        let vendor_ids = [VendorIDFormat {
            // PCI Vendor ID
            format: 0x00,
            // PCI VID
            data: 0x1234,
            // Extra data
            numeric_value: 0xAB,
        }];

        let ctx = MCTPSMBusContext::new(SOURCE_ID, &msg_types, &vendor_ids);
        let mut buf: [u8; 17] = [0; 17];

        let _len =
            ctx.get_response()
                .get_mctp_version_support(CompletionCode::Success, DEST_ID, &mut buf);

        let (msg_type, payload) = ctx.decode_packet(&buf).unwrap();

        assert_eq!(msg_type, MessageType::MCtpControl);
        assert_eq!(payload.len(), 5);
        assert_eq!(payload[0], 1 as u8);
        // Major Version 1
        assert_eq!(payload[1], 0xF1 as u8);
        // Minor Version 3
        assert_eq!(payload[2], 0xF3 as u8);
        // Update 1
        assert_eq!(payload[3], 0xF1 as u8);
    }

    #[test]
    fn test_decode_invalid_response() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x23;

        let msg_types: [u8; 0] = [0; 0];
        let vendor_ids = [VendorIDFormat {
            // PCI Vendor ID
            format: 0x00,
            // PCI VID
            data: 0x1234,
            // Extra data
            numeric_value: 0xAB,
        }];
        let ctx = MCTPSMBusContext::new(SOURCE_ID, &msg_types, &vendor_ids);
        let mut buf: [u8; 17] = [0; 17];

        let _len = ctx.get_response().get_mctp_version_support(
            CompletionCode::ErrorInvalidData,
            DEST_ID,
            &mut buf,
        );

        let error = ctx.decode_packet(&buf);

        match error {
            Ok(_) => {
                panic!("Didn't get the error we expect");
            }
            Err((msg_type, decode_error)) => {
                assert_eq!(msg_type, MessageType::MCtpControl);
                assert_eq!(
                    decode_error,
                    DecodeError::ControlMessage(ControlMessageError::UnsuccessfulCompletionCode(
                        CompletionCode::ErrorInvalidData
                    ))
                );
            }
        }
    }

    #[test]
    fn test_process_request() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x34;

        let msg_types: [u8; 0] = [0; 0];
        let vendor_ids = [VendorIDFormat {
            // PCI Vendor ID
            format: 0x00,
            // PCI VID
            data: 0x1234,
            // Extra data
            numeric_value: 0xAB,
        }];

        let ctx_request = MCTPSMBusContext::new(SOURCE_ID, &msg_types, &vendor_ids);
        let mut buf_request: [u8; 12] = [0; 12];

        let _len = ctx_request.get_request().get_mctp_version_support(
            DEST_ID,
            MCTPVersionQuery::MCTPBaseSpec,
            &mut buf_request,
        );

        let ctx_response = MCTPSMBusContext::new(DEST_ID, &msg_types, &vendor_ids);
        let mut buf_response: [u8; 17] = [0; 17];

        let (_, len) = ctx_response
            .process_packet(&buf_request, &mut buf_response)
            .unwrap();

        assert_eq!(len.unwrap(), 17);

        // Destination address
        assert_eq!(buf_response[0], SOURCE_ID << 1);

        // Byte count
        assert_eq!(buf_response[2], 14);

        // IC and Message Type
        assert_eq!(buf_response[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf_response[9], 0 << 7 | 0 << 6 | 0 << 5 | 0);

        // Command Code
        assert_eq!(buf_response[10], CommandCode::GetMCTPVersionSupport as u8);
        // Completion Code
        assert_eq!(buf_response[11], CompletionCode::Success as u8);

        // Version Entry Count
        assert_eq!(buf_response[12], 1);
        // Major version number
        assert_eq!(buf_response[13], 0xF1);
        // Major version number
        assert_eq!(buf_response[14], 0xF3);
        // Update version number
        assert_eq!(buf_response[15], 0xF1);
        // Alpha byte
        assert_eq!(buf_response[16], 0x00);
    }
}
