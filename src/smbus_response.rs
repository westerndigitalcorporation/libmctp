//! The SMBus specific CMTP response protocol implementation.

use crate::control_packet::{
    CommandCode, CompletionCode, MCTPControlMessageHeader, MCTPGetEndpointIDEndpointIDType,
    MCTPGetEndpointIDEndpointType, MCTPSetEndpointIDAllocationStatus,
    MCTPSetEndpointIDAssignmentStatus,
};
use crate::mctp_traits::SMBusMCTPRequestResponse;
use core::cell::Cell;

/// The context for MCTP SMBus response protocol operations
pub struct MCTPSMBusContextResponse {
    address: u8,
    eid: Cell<u8>,
}

impl SMBusMCTPRequestResponse for MCTPSMBusContextResponse {
    /// Get the address of the device
    ///
    /// Returns the address
    fn get_address(&self) -> u8 {
        self.address
    }

    /// Get the current EID of the device
    ///
    /// Returns the EID
    fn get_eid(&self) -> u8 {
        self.eid.get()
    }

    /// Set the EID of the device
    ///
    /// `eid`: The new eid to use
    fn set_eid(&self, eid: u8) {
        self.eid.replace(eid);
    }
}

impl MCTPSMBusContextResponse {
    /// Create a new SBMust response context
    ///
    /// `address`: The source address of this device
    pub fn new(address: u8) -> Self {
        Self {
            address,
            eid: Cell::new(0x00),
        }
    }

    /// Assigns an EID to the endpoint at the given physical address
    ///
    /// `completion_code`: Indicates the completion code we should return.
    /// `dest_addr`: The address to send the data to.
    /// `assignment_status`: EID assignment status
    /// `allocation_status`: Endpoint ID allocation status
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// EID dynamic Pools are not supported
    ///
    /// Returns the length of the query on success.
    pub fn set_endpoint_id(
        &self,
        completion_code: CompletionCode,
        dest_addr: u8,
        assignment_status: MCTPSetEndpointIDAssignmentStatus,
        allocation_status: MCTPSetEndpointIDAllocationStatus,
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(false, false, 0, CommandCode::SetEndpointID);
        let message_header = Some(&(command_header.0[..]));
        // Return
        //  * Completion code
        //  * EID Assignment Status/Endpoint ID allocation status
        //  * EID Setting
        //  * EID Pool Size
        let mut message_data: [u8; 4] = [
            completion_code as u8,
            allocation_status as u8,
            self.eid.get(),
            0x00,
        ];

        if assignment_status == MCTPSetEndpointIDAssignmentStatus::Rejected {
            message_data[1] |= 1 << 4;
        }

        self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Returns the EID presently assigned to an endpoint. Also returns
    /// information about what type the endpoint is and its level of use of
    /// static EIDs.
    ///
    /// `completion_code`: Indicates the completion code we should return.
    /// `dest_addr`: The address to send the data to.
    /// `endpoint_type`: Endpoint Type
    /// `endpoint_id_type`: Endpoint ID Type
    /// `fairness_support`: fairness arbitration support (see 6.13)
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn get_endpoint_id(
        &self,
        completion_code: CompletionCode,
        dest_addr: u8,
        endpoint_type: MCTPGetEndpointIDEndpointType,
        endpoint_id_type: MCTPGetEndpointIDEndpointIDType,
        fairness_support: bool,
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(false, false, 0, CommandCode::GetEndpointID);
        let message_header = Some(&(command_header.0[..]));
        // Return
        //  * Completion code
        //  * Endpoint ID
        //  * Endpoint Type (single endpoint)
        //  * Medium-Specific Information
        let message_data: [u8; 4] = [
            completion_code as u8,
            self.eid.get(),
            (endpoint_type as u8) << 4 | endpoint_id_type as u8,
            fairness_support as u8,
        ];

        self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Retrieves a per-device unique UUID associated with the endpoint
    ///
    /// `completion_code`: Indicates the completion code we should return.
    /// `dest_addr`: The address to send the data to.
    /// `uuid`: A reference to an array containing the UUID
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn get_endpoint_uuid(
        &self,
        completion_code: CompletionCode,
        dest_addr: u8,
        uuid: &[u8; 16],
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(false, false, 0, CommandCode::GetEndpointUUID);
        let message_header = Some(&(command_header.0[..]));
        // Return
        //  * Completion code
        //  * UUID
        //  * Endpoint Type (single endpoint)
        //  * Medium-Specific Information
        let mut message_data: [u8; 17] = [0; 17];
        message_data[0] = completion_code as u8;
        message_data[1..17].copy_from_slice(uuid);

        self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Generate a response to the MCTP Version request supported by a device.
    ///
    /// `completion_code`: Indicates the completion code we should return.
    /// `dest_addr`: The address to send the data to.
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the response.
    pub fn get_mctp_version_support(
        &self,
        completion_code: CompletionCode,
        dest_addr: u8,
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(false, false, 0, CommandCode::GetMCTPVersionSupport);
        let message_header = Some(&(command_header.0[..]));
        // Return
        // Completion code
        // Version Number entry count: 1
        // Version: 1.3.1
        let message_data: [u8; 6] = [completion_code as u8, 1, 0xF1, 0xF3, 0xF1, 0x00];

        self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Lists the message types that an endpoint supports
    ///
    /// `completion_code`: Indicates the completion code we should return.
    /// `dest_addr`: The address to send the data to.
    /// `supported_msg_types`: A slice to an array of bytes listing the
    ///  supported MCTP message types, this should NOT include the control
    ///  message type (0). This implementation supports a maximum of 30
    ///  control messages.
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the response.
    pub fn get_message_type_suport(
        &self,
        completion_code: CompletionCode,
        dest_addr: u8,
        supported_msg_types: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(false, false, 0, CommandCode::GetMessageTypeSupport);
        let message_header = Some(&(command_header.0[..]));
        // Return
        //  * Completion code
        //  * MCTP Message Type Count
        //  * List of Message Type numbers
        let msg_type_count = supported_msg_types.len();
        let mut message_data: [u8; 32] = [0; 32];
        message_data[0] = completion_code as u8;
        message_data[1] = msg_type_count as u8;

        if supported_msg_types.len() > 30 {
            return Err(());
        }

        for (i, d) in supported_msg_types.iter().enumerate() {
            message_data[2 + i] = *d;
        }

        self.generate_control_packet_bytes(
            dest_addr,
            &message_header,
            &message_data[0..(msg_type_count + 2)],
            buf,
        )
    }

    /// Used to discover an MCTP endpoint’s vendor-specific MCTP extensions and capabilities
    ///
    /// `completion_code`: Indicates the completion code we should return.
    /// `dest_addr`: The address to send the data to.
    /// `vendor_id_selector`: The vendor ID set returned.
    ///  Indicates the specific capability set requested. Indices start at
    ///  0x00 and increase monotonically by 1. If the responding endpoint has
    ///  one or more capability sets with indices greater than the requested
    ///  index, it increments the requested index by 1 and returns the
    ///  resulting value in the response message. The requesting endpoint uses
    ///  the returned value to request the next capability set.
    /// `vendor_id`: A slice to an array of bytes listing a
    ///  structured field of variable length that identifies the vendor ID
    ///  format (presently PCI or IANA) and the ID of the vendor that defined
    ///  the capability set.
    ///  This should be either 3 (PCI Vendor ID) or 5 (IANA Enterprise
    ///  Number) bytes long.
    ///  If using a 16-bit numeric value or bit field, as specified by the
    ///  vendor or organization identified by the vendor ID this should
    ///  be include in this slice, increasing the total length by 2.
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the response.
    pub fn get_vendor_defined_message_support(
        &self,
        completion_code: CompletionCode,
        dest_addr: u8,
        vendor_id_selector: u8,
        vendor_id: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        let command_header = MCTPControlMessageHeader::new(
            false,
            false,
            0,
            CommandCode::GetVendorDefinedMessageSupport,
        );
        let message_header = Some(&(command_header.0[..]));
        // Return
        //  * Completion code
        //  * Vendor ID Set Selector
        //  * Vendor ID (variable length, between 3 and 5 bytes)
        //  * 16-bit numeric value or bit field, as specified by the vendor
        //    or organization identified by the vendor ID
        let vendor_length = vendor_id.len();
        let mut message_data: [u8; 9] = [
            completion_code as u8,
            vendor_id_selector,
            0, // Vendor ID Format
            0, // PCI Vendor ID or IANA Enterprise Number
            0, // PCI Vendor ID or IANA Enterprise Number
            0, // IANA Enterprise Number or numeric value
            0, // IANA Enterprise Number or numeric value
            0, // numeric value (IANA)
            0, // numeric value (IANA)
        ];

        for (i, d) in vendor_id.iter().enumerate() {
            message_data[2 + i] = *d;
        }

        self.generate_control_packet_bytes(
            dest_addr,
            &message_header,
            &message_data[0..(vendor_length + 2)],
            buf,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base_packet::MessageType;
    use crate::smbus_proto::{HDR_VERSION, MCTP_SMBUS_COMMAND_CODE};

    #[test]
    fn test_generate_smbus_header() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x44;

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
        let buf = header.to_bytes();

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
    fn test_set_endpoint_id() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x23;
        const EID: u8 = 0x78;

        let ctx = MCTPSMBusContextResponse::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        ctx.set_eid(EID);

        let len = ctx
            .set_endpoint_id(
                CompletionCode::Success,
                DEST_ID,
                MCTPSetEndpointIDAssignmentStatus::Accpeted,
                MCTPSetEndpointIDAllocationStatus::NoIDPool,
                &mut buf,
            )
            .unwrap();

        assert_eq!(len, 16);

        // Byte count
        assert_eq!(buf[2], 12);

        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 0 << 7 | 0 << 6 | 0 << 5 | 0);

        // Command Code
        assert_eq!(buf[10], CommandCode::SetEndpointID as u8);
        // Completion Code
        assert_eq!(buf[11], CompletionCode::Success as u8);

        // EID Status
        assert_eq!(
            buf[12],
            (MCTPSetEndpointIDAssignmentStatus::Accpeted as u8) << 4
                | MCTPSetEndpointIDAllocationStatus::NoIDPool as u8
        );
        // EID Setting
        assert_eq!(buf[13], ctx.get_eid());
        // EID Pool Size
        assert_eq!(buf[14], 0x00);
    }

    #[test]
    fn test_get_endpoint_id() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x23;
        const EID: u8 = 0x78;

        let ctx = MCTPSMBusContextResponse::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        ctx.set_eid(EID);

        let len = ctx
            .get_endpoint_id(
                CompletionCode::Success,
                DEST_ID,
                MCTPGetEndpointIDEndpointType::Simple,
                MCTPGetEndpointIDEndpointIDType::DynamicEID,
                true,
                &mut buf,
            )
            .unwrap();

        assert_eq!(len, 16);

        // Byte count
        assert_eq!(buf[2], 12);

        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 0 << 7 | 0 << 6 | 0 << 5 | 0);

        // Command Code
        assert_eq!(buf[10], CommandCode::GetEndpointID as u8);
        // Completion Code
        assert_eq!(buf[11], CompletionCode::Success as u8);

        // Endpoint ID
        assert_eq!(buf[12], EID);
        // Endpoint Type (Simple endpoint, Dynamic EID)
        assert_eq!(buf[13], 0);
        // Medium Specific Info
        assert_eq!(buf[14], 0x01);
    }

    #[test]
    fn test_get_endpoint_uuid() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x23;
        const EID: u8 = 0x78;

        let ctx = MCTPSMBusContextResponse::new(SOURCE_ID);
        let mut buf: [u8; 32] = [0; 32];

        ctx.set_eid(EID);

        let uuid: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];

        let len = ctx
            .get_endpoint_uuid(CompletionCode::Success, DEST_ID, &uuid, &mut buf)
            .unwrap();

        assert_eq!(len, 29);

        // Byte count
        assert_eq!(buf[2], 25);

        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 0 << 7 | 0 << 6 | 0 << 5 | 0);

        // Command Code
        assert_eq!(buf[10], CommandCode::GetEndpointUUID as u8);
        // Completion Code
        assert_eq!(buf[11], CompletionCode::Success as u8);

        // Endpoint ID
        for (i, d) in uuid.iter().enumerate() {
            assert_eq!(buf[12 + i], *d);
        }
    }

    #[test]
    fn test_get_mctp_version_support() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x23;

        let ctx = MCTPSMBusContextResponse::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx
            .get_mctp_version_support(CompletionCode::Success, DEST_ID, &mut buf)
            .unwrap();

        assert_eq!(len, 18);

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

    #[test]
    fn test_get_message_type_suport() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x23;

        let ctx = MCTPSMBusContextResponse::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let msg_types = [0x7E];

        let len = ctx
            .get_message_type_suport(CompletionCode::Success, DEST_ID, &msg_types, &mut buf)
            .unwrap();

        assert_eq!(len, 15);

        // Byte count
        assert_eq!(buf[2], 11);

        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 0 << 7 | 0 << 6 | 0 << 5 | 0);

        // Command Code
        assert_eq!(buf[10], CommandCode::GetMessageTypeSupport as u8);
        // Completion Code
        assert_eq!(buf[11], CompletionCode::Success as u8);

        // Version Entry Count
        assert_eq!(buf[12], msg_types.len() as u8);
        assert_eq!(buf[13], msg_types[0]);
    }

    #[test]
    fn test_get_vendor_defined_message_support() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x23;

        let ctx = MCTPSMBusContextResponse::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let vendor_id = [
            0x00, // PCI Vendor
            0xAB, 0xBC, 0x12, 0x34,
        ];

        let len = ctx
            .get_vendor_defined_message_support(
                CompletionCode::Success,
                DEST_ID,
                0xFF,
                &vendor_id,
                &mut buf,
            )
            .unwrap();

        assert_eq!(len, 19);

        // Byte count
        assert_eq!(buf[2], 15);

        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 0 << 7 | 0 << 6 | 0 << 5 | 0);

        // Command Code
        assert_eq!(buf[10], CommandCode::GetVendorDefinedMessageSupport as u8);
        // Completion Code
        assert_eq!(buf[11], CompletionCode::Success as u8);

        // Vendor ID Set Selector
        assert_eq!(buf[12], 0xFF);

        // Vendor ID
        for (i, d) in vendor_id.iter().enumerate() {
            assert_eq!(buf[13 + i], *d);
        }
    }
}
