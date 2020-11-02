//! The SMBus specific CMTP request protocol implementation.

use crate::control_packet::{
    CommandCode, MCTPControlMessageHeader, MCTPSetEndpointIDOperations, MCTPVersionQuery,
};
use crate::mctp_traits::SMBusMCTPRequestResponse;

/// The context for MCTP SMBus request protocol operations
pub struct MCTPSMBusContextRequest {
    address: u8,
}

impl SMBusMCTPRequestResponse for MCTPSMBusContextRequest {
    fn get_address(&self) -> u8 {
        self.address
    }
}

impl MCTPSMBusContextRequest {
    /// Create a new SBMust request context
    ///
    /// `address`: The source address of this device
    pub fn new(address: u8) -> Self {
        Self { address }
    }

    /// Assigns an EID to the endpoint at the given physical address
    ///
    /// `dest_addr`: The address to send the data to.
    /// `operation`: The operation to use to set the ID
    /// `eid`: The ID to set
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn set_endpoint_id(
        &self,
        dest_addr: u8,
        operation: MCTPSetEndpointIDOperations,
        eid: u8,
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(true, false, 0, CommandCode::SetEndpointID);
        let message_header = Some(&(command_header.0[..]));

        if eid == 0xFF || eid == 0x00 {
            // These values are reserved
            return Err(());
        }

        let message_data: [u8; 2] = [operation as u8, eid];

        self.generate_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Returns the EID presently assigned to an endpoint. Also returns
    /// information about what type the endpoint is and its level of use of
    /// static EIDs.
    ///
    /// `dest_addr`: The address to send the data to.
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn get_endpoint_id(&self, dest_addr: u8, buf: &mut [u8]) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(true, false, 0, CommandCode::GetEndpointID);
        let message_header = Some(&(command_header.0[..]));

        let message_data: [u8; 0] = [0; 0];

        self.generate_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Retrieves a per-device unique UUID associated with the endpoint
    ///
    /// `dest_addr`: The address to send the data to.
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn get_endpoint_uuid(&self, dest_addr: u8, buf: &mut [u8]) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(true, false, 0, CommandCode::GetEndpointUUID);
        let message_header = Some(&(command_header.0[..]));

        let message_data: [u8; 0] = [0; 0];

        self.generate_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Generate a packet to get the MCTP Versions supported by a device.
    ///
    /// `dest_addr`: The address to send the data to.
    /// `query`: The type of version query.
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn get_mctp_version_support(
        &self,
        dest_addr: u8,
        query: MCTPVersionQuery,
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(true, false, 0, CommandCode::GetMCTPVersionSupport);
        let message_header = Some(&(command_header.0[..]));

        let message_data: [u8; 1] = [query as u8];

        self.generate_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Lists the message types that an endpoint supports
    ///
    /// `dest_addr`: The address to send the data to.
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn get_message_type_suport(&self, dest_addr: u8, buf: &mut [u8]) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(true, false, 0, CommandCode::GetMessageTypeSupport);
        let message_header = Some(&(command_header.0[..]));

        let message_data: [u8; 0] = [0; 0];

        self.generate_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Used to discover an MCTP endpoint’s vendor-specific MCTP extensions and capabilities
    ///
    /// `dest_addr`: The address to send the data to.
    /// `vendor_id`: The vendor ID to query
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn get_vendor_defined_message_support(
        &self,
        dest_addr: u8,
        vendor_id: u8,
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        let command_header = MCTPControlMessageHeader::new(
            true,
            false,
            0,
            CommandCode::GetVendorDefinedMessageSupport,
        );
        let message_header = Some(&(command_header.0[..]));

        let message_data: [u8; 1] = [vendor_id as u8];

        self.generate_packet_bytes(dest_addr, &message_header, &message_data, buf)
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

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);

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

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);

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
        const EID: u8 = 0x56;

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx
            .set_endpoint_id(DEST_ID, MCTPSetEndpointIDOperations::SetEID, EID, &mut buf)
            .unwrap();

        assert_eq!(len, 13);
        // Byte count
        assert_eq!(buf[2], 10);
        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 1 << 7 | 0 << 6 | 0 << 5 | 0);
        // Command Code
        assert_eq!(buf[10], CommandCode::SetEndpointID as u8);
        // Operation
        assert_eq!(buf[11], MCTPSetEndpointIDOperations::SetEID as u8);
        // Endpoint ID
        assert_eq!(buf[12], EID);
    }

    #[test]
    fn test_get_endpoint_id() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x23;

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx.get_endpoint_id(DEST_ID, &mut buf).unwrap();

        assert_eq!(len, 11);
        // Byte count
        assert_eq!(buf[2], 8);
        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 1 << 7 | 0 << 6 | 0 << 5 | 0);
        // Command Code
        assert_eq!(buf[10], CommandCode::GetEndpointID as u8);
    }

    #[test]
    fn test_get_endpoint_uuid() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x23;

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx.get_endpoint_uuid(DEST_ID, &mut buf).unwrap();

        assert_eq!(len, 11);
        // Byte count
        assert_eq!(buf[2], 8);
        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 1 << 7 | 0 << 6 | 0 << 5 | 0);
        // Command Code
        assert_eq!(buf[10], CommandCode::GetEndpointUUID as u8);
    }

    #[test]
    fn test_get_mctp_version_support() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x23;

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx
            .get_mctp_version_support(DEST_ID, MCTPVersionQuery::MCTPBaseSpec, &mut buf)
            .unwrap();

        assert_eq!(len, 12);
        // Byte count
        assert_eq!(buf[2], 9);
        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 1 << 7 | 0 << 6 | 0 << 5 | 0);
        // Command Code
        assert_eq!(buf[10], CommandCode::GetMCTPVersionSupport as u8);
        // Command query
        assert_eq!(buf[11], MCTPVersionQuery::MCTPBaseSpec as u8);
    }

    #[test]
    fn test_get_message_type_suport() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x23;

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx.get_message_type_suport(DEST_ID, &mut buf).unwrap();

        assert_eq!(len, 11);
        // Byte count
        assert_eq!(buf[2], 8);
        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 1 << 7 | 0 << 6 | 0 << 5 | 0);
        // Command Code
        assert_eq!(buf[10], CommandCode::GetMessageTypeSupport as u8);
    }

    #[test]
    fn test_get_vendor_defined_message_support() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x23;
        const VENDOR_ID: u8 = 0x7E;

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx
            .get_vendor_defined_message_support(DEST_ID, VENDOR_ID, &mut buf)
            .unwrap();

        assert_eq!(len, 12);
        // Byte count
        assert_eq!(buf[2], 9);
        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 1 << 7 | 0 << 6 | 0 << 5 | 0);
        // Command Code
        assert_eq!(buf[10], CommandCode::GetVendorDefinedMessageSupport as u8);
        // Vendor ID
        assert_eq!(buf[11], VENDOR_ID);
    }
}
