//! The SMBus specific CMTP response protocol implementation.

use crate::control_packet::{
    CommandCode, CompletionCode, MCTPControlMessageHeader, MCTPSetEndpointIDAllocationStatus,
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
        dest_addr: u8,
        assignment_status: MCTPSetEndpointIDAssignmentStatus,
        allocation_status: MCTPSetEndpointIDAllocationStatus,
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(false, false, 0, CommandCode::SetEndpointID);
        let message_header = Some(&(command_header.0[..]));
        // Return
        // Completion code
        // EID Assignment Status/Endpoint ID allocation status
        // EID Setting
        // EID Pool Size
        let mut message_data: [u8; 4] = [
            CompletionCode::Success as u8,
            allocation_status as u8,
            self.eid.get(),
            0x00,
        ];

        if assignment_status == MCTPSetEndpointIDAssignmentStatus::Rejected {
            message_data[1] |= 1 << 4;
        }

        self.generate_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Returns the EID presently assigned to an endpoint. Also returns
    /// information about what type the endpoint is and its level of use of
    /// static EIDs.
    pub fn get_endpoint_id(&self, _dest_addr: u8) -> usize {
        unimplemented!()
    }

    /// Retrieves a per-device unique UUID associated withthe endpoint
    pub fn get_endpoint_uuid(&self, _dest_addr: u8) -> usize {
        unimplemented!()
    }

    /// Generate a response to the MCTP Version request supported by a device.
    ///
    /// `dest_addr`: The address to send the data to.
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the response.
    pub fn get_mctp_version_support(&self, dest_addr: u8, buf: &mut [u8]) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(false, false, 0, CommandCode::GetMCTPVersionSupport);
        let message_header = Some(&(command_header.0[..]));
        // Return
        // Completion code
        // Version Number entry count: 1
        // Version: 1.3.1
        let message_data: [u8; 6] = [CompletionCode::Success as u8, 1, 0xF1, 0xF3, 0xF1, 0x00];

        self.generate_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Lists the message types that an endpoint supports
    pub fn get_message_type_suport(&self, _dest_addr: u8) -> usize {
        unimplemented!()
    }

    /// Used to discover an MCTP endpoint’s vendor-specific MCTP extensions and capabilities
    pub fn get_vendor_defined_message_support(&self, _dest_addr: u8) -> usize {
        unimplemented!()
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
        const SOURCE_ID: u8 = 0x23;

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
        let buf = header.0;

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
                DEST_ID,
                MCTPSetEndpointIDAssignmentStatus::Accpeted,
                MCTPSetEndpointIDAllocationStatus::NoIDPool,
                &mut buf,
            )
            .unwrap();

        assert_eq!(len, 15);

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
    fn test_get_mctp_version_support() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x23;

        let ctx = MCTPSMBusContextResponse::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx.get_mctp_version_support(DEST_ID, &mut buf).unwrap();

        assert_eq!(len, 17);

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
}
