//! The SMBus specific CMTP request protocol implementation.

use crate::base_packet::MessageType;
use crate::control_packet::{
    AllocateEndpointIDOperation, CommandCode, MCTPControlMessageHeader,
    MCTPSetEndpointIDOperations, MCTPVersionQuery,
};
use crate::mctp_traits::SMBusMCTPRequestResponse;
use crate::smbus_proto::SMBusRoutingInformationUpdateEntry;
use crate::vendor_packets::{IANAMessageFormat, PCIMessageFormat, VendorIDFormat};
use core::cell::Cell;

/// The context for MCTP SMBus request protocol operations
pub struct MCTPSMBusContextRequest {
    address: u8,
    eid: Cell<u8>,
}

impl SMBusMCTPRequestResponse for MCTPSMBusContextRequest {
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

impl MCTPSMBusContextRequest {
    /// Create a new SBMust request context
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

        self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf)
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

        self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf)
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

        self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf)
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

        self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf)
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

        self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf)
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

        let message_data: [u8; 1] = [vendor_id];

        self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Used to get the physical address associated with a given EID
    ///
    /// `dest_addr`: The address to send the data to.
    /// `endpont_id`: The EID that the bus owner is being asked to resolve.
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn resolve_endpoint_id(
        &self,
        dest_addr: u8,
        endpont_id: u8,
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(true, false, 0, CommandCode::ResolveEndpointID);
        let message_header = Some(&(command_header.0[..]));

        let message_data: [u8; 1] = [endpont_id];

        self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Used by the bus owner to allocate a pool of EIDs to an MCTP bridge
    ///
    /// `dest_addr`: The address to send the data to.
    /// `operation`: The type of operation
    /// `pool_size`: Number of Endpoint IDs(Allocated Pool Size)
    /// `starting_eid`: Specifies the starting EID for the range of EIDs being
    ///                 allocated in the pool
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn allocate_endpoint_ids(
        &self,
        dest_addr: u8,
        operation: AllocateEndpointIDOperation,
        pool_size: u8,
        starting_eid: u8,
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(true, false, 0, CommandCode::AllocateEndpointIDs);
        let message_header = Some(&(command_header.0[..]));

        let message_data: [u8; 3] = [operation as u8, pool_size, starting_eid];

        self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Used by the bus owner to extend or update the routing information that
    /// is maintained by an MCTP bridge
    ///
    /// `dest_addr`: The address to send the data to.
    /// `entries`: One or more update entries, based on the given count
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn routing_information_update(
        &self,
        dest_addr: u8,
        entries: &[SMBusRoutingInformationUpdateEntry<[u8; 4]>],
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(true, false, 0, CommandCode::RoutingInformationUpdate);
        let message_header = Some(&(command_header.0[..]));

        let num_entries = entries.len();
        let mut message_data: [u8; 32] = [0; 32];
        message_data[0] = num_entries as u8;

        if num_entries * 4 > 31 {
            return Err(());
        }

        for (i, entry) in entries.iter().enumerate() {
            let offset = 1 + (i * 4);
            message_data[offset..(offset + 4)].copy_from_slice(&entry.0);
        }

        self.generate_control_packet_bytes(
            dest_addr,
            &message_header,
            &message_data[0..(1 + num_entries * 4)],
            buf,
        )
    }

    /// Used to request an MCTP bridge to return data corresponding to its
    /// present routing table entries
    ///
    /// `dest_addr`: The address to send the data to.
    /// `entry_handle`: Entry Handle (0x00to access first entries in table)
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn get_routing_table_entries(
        &self,
        dest_addr: u8,
        entry_handle: u8,
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(true, false, 0, CommandCode::GetRoutingTableEntries);
        let message_header = Some(&(command_header.0[..]));

        let message_data: [u8; 1] = [entry_handle];

        self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Used to direct endpoints to clear their “discovered”flags to enable
    /// them to respond to the Endpoint Discovery command
    ///
    /// `dest_addr`: The address to send the data to.
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn prepare_for_endpoint_discovery(
        &self,
        dest_addr: u8,
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(true, false, 0, CommandCode::PrepareForEndpointDiscovery);
        let message_header = Some(&(command_header.0[..]));

        let message_data: [u8; 0] = [0; 0];

        self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Used to discover MCTP-capable devices on a bus, provided that another
    /// discovery mechanism is not defined for the particular physical medium
    ///
    /// `dest_addr`: The address to send the data to.
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn endpoint_discovery(&self, dest_addr: u8, buf: &mut [u8]) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(true, false, 0, CommandCode::EndpointDiscovery);
        let message_header = Some(&(command_header.0[..]));

        let message_data: [u8; 0] = [0; 0];

        self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Used to notify the bus owner that an MCTP device has become
    /// available on the bus
    ///
    /// `dest_addr`: The address to send the data to.
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn discovery_notify(&self, dest_addr: u8, buf: &mut [u8]) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(true, false, 0, CommandCode::DiscoveryNotify);
        let message_header = Some(&(command_header.0[..]));

        let message_data: [u8; 0] = [0; 0];

        self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Used to get the MCTP networkID
    ///
    /// `dest_addr`: The address to send the data to.
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn get_network_id(&self, dest_addr: u8, buf: &mut [u8]) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(true, false, 0, CommandCode::GetNetworkID);
        let message_header = Some(&(command_header.0[..]));

        let message_data: [u8; 0] = [0; 0];

        self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Used to discover what bridges, if any, are in the path to a given
    /// target endpoint and what transmission unit sizes the bridges will pass
    /// for a given message type when routing to the target endpoint
    ///
    /// `dest_addr`: The address to send the data to.
    /// `target_eid': Target Endpoint ID
    /// `msg_type`: Message type for which transmission unit information is being requested
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn query_hop(
        &self,
        dest_addr: u8,
        target_eid: u8,
        msg_type: MessageType,
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(true, false, 0, CommandCode::GetNetworkID);
        let message_header = Some(&(command_header.0[..]));

        let message_data: [u8; 2] = [target_eid, msg_type as u8];

        self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Used by endpoints to find another endpoint matching an endpoint
    /// that uses a specific UUID
    ///
    /// `dest_addr`: The address to send the data to.
    /// `uuid`: A reference to an array containing the UUID to request
    /// `entry_handle`: Entry Handle (0x00 to access first entries in table)
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn resolve_uuid(
        &self,
        dest_addr: u8,
        uuid: &[u8; 16],
        entry_handle: u8,
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(true, false, 0, CommandCode::ResolveUUID);
        let message_header = Some(&(command_header.0[..]));

        let mut message_data: [u8; 17] = [0; 17];
        message_data[0..16].copy_from_slice(uuid);
        message_data[16] = entry_handle;

        self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Used to discover the data rate limit settings of the given target for
    /// incoming messages.
    ///
    /// `dest_addr`: The address to send the data to.
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn query_rate_limit(&self, dest_addr: u8, buf: &mut [u8]) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(true, false, 0, CommandCode::QueryRateLimit);
        let message_header = Some(&(command_header.0[..]));

        let message_data: [u8; 0] = [0; 0];

        self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf)
    }

    /// Used to request the allowed transmit data rate limit for the
    /// given endpoint for outgoing messages.
    ///
    /// `dest_addr`: The address to send the data to.
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn request_tx_rate_limit(&self, dest_addr: u8, buf: &mut [u8]) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(true, false, 0, CommandCode::RequestTXRateLimit);
        let message_header = Some(&(command_header.0[..]));

        let message_data: [u8; 0] = [0; 0];

        let _ = self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf);

        unimplemented!()
    }

    /// Used to update the receiving side on change to the transmit data
    /// rate which was not requested by the receiver
    ///
    /// `dest_addr`: The address to send the data to.
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn update_rate_limmit(&self, dest_addr: u8, buf: &mut [u8]) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(true, false, 0, CommandCode::RequestTXRateLimit);
        let message_header = Some(&(command_header.0[..]));

        let message_data: [u8; 0] = [0; 0];

        let _ = self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf);

        unimplemented!()
    }

    /// Used to discover the existing device MCTP interfaces
    ///
    /// `dest_addr`: The address to send the data to.
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn query_supported_interfaces(&self, dest_addr: u8, buf: &mut [u8]) -> Result<usize, ()> {
        let command_header =
            MCTPControlMessageHeader::new(true, false, 0, CommandCode::RequestTXRateLimit);
        let message_header = Some(&(command_header.0[..]));

        let message_data: [u8; 0] = [0; 0];

        let _ = self.generate_control_packet_bytes(dest_addr, &message_header, &message_data, buf);

        unimplemented!()
    }

    /// Send a vendor defined request
    ///
    /// `dest_addr`: The address to send the data to.
    /// `format`: A reference to the VendorIDFormat used to send the message
    /// `msg`: The vendor defined message that should be sent
    /// `buf`: A mutable buffer to store the request bytes.
    ///
    /// Returns the length of the query on success.
    pub fn vendor_defined(
        &self,
        dest_addr: u8,
        format: &VendorIDFormat,
        msg: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        if format.format == 0 {
            /* PCI message format */
            let pci_msg_header = PCIMessageFormat::new(format.data as u16);
            let message_header = Some(&(pci_msg_header.0[..]));

            #[cfg(test)]
            println!("message_header: {:#x?}", message_header);

            self.generate_pci_msg_packet_bytes(dest_addr, &message_header, msg, buf)
        } else if format.format == 1 {
            /* IANA message format */
            let iana_msg_header = IANAMessageFormat::new(format.data);
            let message_header = Some(&(iana_msg_header.0[..]));

            self.generate_iana_msg_packet_bytes(dest_addr, &message_header, msg, buf)
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_packet::RoutingInformationUpdateEntryType;
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
        const EID: u8 = 0x56;

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx
            .set_endpoint_id(DEST_ID, MCTPSetEndpointIDOperations::SetEID, EID, &mut buf)
            .unwrap();

        assert_eq!(len, 14);
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

        assert_eq!(len, 12);
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

        assert_eq!(len, 12);
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

        assert_eq!(len, 13);
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

        assert_eq!(len, 12);
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
        const VENDOR_ID: u8 = 0x00;

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx
            .get_vendor_defined_message_support(DEST_ID, VENDOR_ID, &mut buf)
            .unwrap();

        assert_eq!(len, 13);
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

    #[test]
    fn test_resolve_endpoint_id() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x34;
        const EID: u8 = 0x56;

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx.resolve_endpoint_id(DEST_ID, EID, &mut buf).unwrap();

        assert_eq!(len, 13);
        // Byte count
        assert_eq!(buf[2], 9);
        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 1 << 7 | 0 << 6 | 0 << 5 | 0);
        // Command Code
        assert_eq!(buf[10], CommandCode::ResolveEndpointID as u8);
        // EID
        assert_eq!(buf[11], EID);
    }

    #[test]
    fn test_allocate_endpoint_ids() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x34;

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx
            .allocate_endpoint_ids(
                DEST_ID,
                AllocateEndpointIDOperation::AllocateEIDs,
                3,
                1,
                &mut buf,
            )
            .unwrap();

        assert_eq!(len, 15);
        // Byte count
        assert_eq!(buf[2], 11);
        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 1 << 7 | 0 << 6 | 0 << 5 | 0);
        // Command Code
        assert_eq!(buf[10], CommandCode::AllocateEndpointIDs as u8);
        // Operation
        assert_eq!(buf[11], AllocateEndpointIDOperation::AllocateEIDs as u8);
        // Pool Size
        assert_eq!(buf[12], 3);
        // Starting ID
        assert_eq!(buf[13], 1);
    }

    #[test]
    fn test_routing_information_update() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x34;

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let entries = [SMBusRoutingInformationUpdateEntry::new(
            RoutingInformationUpdateEntryType::EIDRangeNotIncludeBridge,
            1,
            1,
            SOURCE_ID,
        )];

        let len = ctx
            .routing_information_update(DEST_ID, &entries, &mut buf)
            .unwrap();

        assert_eq!(len, 17);
        // Byte count
        assert_eq!(buf[2], 13);
        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 1 << 7 | 0 << 6 | 0 << 5 | 0);
        // Command Code
        assert_eq!(buf[10], CommandCode::RoutingInformationUpdate as u8);
        // Count
        assert_eq!(buf[11], 1);
        // Entry Type
        assert_eq!(
            buf[12],
            RoutingInformationUpdateEntryType::EIDRangeNotIncludeBridge as u8
        );
        // Size of EID Range
        assert_eq!(buf[13], 1);
        // First EID
        assert_eq!(buf[14], 1);
        // Physical Address
        assert_eq!(buf[15], SOURCE_ID);
    }

    #[test]
    fn test_get_routing_table_entries() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x34;

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx
            .get_routing_table_entries(DEST_ID, 0x00, &mut buf)
            .unwrap();

        assert_eq!(len, 13);
        // Byte count
        assert_eq!(buf[2], 9);
        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 1 << 7 | 0 << 6 | 0 << 5 | 0);
        // Command Code
        assert_eq!(buf[10], CommandCode::GetRoutingTableEntries as u8);
        // Entry Handle
        assert_eq!(buf[11], 0x00);
    }

    #[test]
    fn test_prepare_for_endpoint_discovery() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x34;

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx
            .prepare_for_endpoint_discovery(DEST_ID, &mut buf)
            .unwrap();

        assert_eq!(len, 12);
        // Byte count
        assert_eq!(buf[2], 8);
        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 1 << 7 | 0 << 6 | 0 << 5 | 0);
        // Command Code
        assert_eq!(buf[10], CommandCode::PrepareForEndpointDiscovery as u8);
    }

    #[test]
    fn test_endpoint_discovery() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x34;

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx.endpoint_discovery(DEST_ID, &mut buf).unwrap();

        assert_eq!(len, 12);
        // Byte count
        assert_eq!(buf[2], 8);
        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 1 << 7 | 0 << 6 | 0 << 5 | 0);
        // Command Code
        assert_eq!(buf[10], CommandCode::EndpointDiscovery as u8);
    }

    #[test]
    fn test_discovery_notify() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x34;

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx.discovery_notify(DEST_ID, &mut buf).unwrap();

        assert_eq!(len, 12);
        // Byte count
        assert_eq!(buf[2], 8);
        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 1 << 7 | 0 << 6 | 0 << 5 | 0);
        // Command Code
        assert_eq!(buf[10], CommandCode::DiscoveryNotify as u8);
    }

    #[test]
    fn test_get_network_id() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x34;

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx.get_network_id(DEST_ID, &mut buf).unwrap();

        assert_eq!(len, 12);
        // Byte count
        assert_eq!(buf[2], 8);
        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 1 << 7 | 0 << 6 | 0 << 5 | 0);
        // Command Code
        assert_eq!(buf[10], CommandCode::GetNetworkID as u8);
    }

    #[test]
    fn test_query_hop() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x34;
        const TARGET_EID: u8 = 0x92;

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx
            .query_hop(DEST_ID, TARGET_EID, MessageType::MCtpControl, &mut buf)
            .unwrap();

        assert_eq!(len, 14);
        // Byte count
        assert_eq!(buf[2], 10);
        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 1 << 7 | 0 << 6 | 0 << 5 | 0);
        // Command Code
        assert_eq!(buf[10], CommandCode::GetNetworkID as u8);
        // Target Endpoint ID
        assert_eq!(buf[11], TARGET_EID);
        // Message Type
        assert_eq!(buf[12], MessageType::MCtpControl as u8);
    }

    #[test]
    fn test_resolve_uuid() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x34;

        let uuid: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);
        let mut buf: [u8; 29] = [0; 29];

        let len = ctx.resolve_uuid(DEST_ID, &uuid, 0x00, &mut buf).unwrap();

        assert_eq!(len, 29);
        // Byte count
        assert_eq!(buf[2], 25);
        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 1 << 7 | 0 << 6 | 0 << 5 | 0);
        // Command Code
        assert_eq!(buf[10], CommandCode::ResolveUUID as u8);
        // Endpoint ID
        for (i, d) in uuid.iter().enumerate() {
            assert_eq!(buf[11 + i], *d);
        }
        // Entry Handle
        assert_eq!(buf[27], 0);
    }

    #[test]
    fn test_query_rate_limit() {
        const DEST_ID: u8 = 0x23;
        const SOURCE_ID: u8 = 0x34;

        let ctx = MCTPSMBusContextRequest::new(SOURCE_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx.query_rate_limit(DEST_ID, &mut buf).unwrap();

        assert_eq!(len, 12);
        // Byte count
        assert_eq!(buf[2], 8);
        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::MCtpControl as u8);
        // Rq, D, rsvd and Instance ID
        assert_eq!(buf[9], 1 << 7 | 0 << 6 | 0 << 5 | 0);
        // Command Code
        assert_eq!(buf[10], CommandCode::QueryRateLimit as u8);
    }

    #[test]
    fn test_vendor_defined() {
        const DEST_ID: u8 = 0x23;
        const VENDOR_ID: VendorIDFormat = VendorIDFormat {
            // PCI Vendor ID
            format: 0x00,
            // PCI VID
            data: 0x1414,
            // Extra data
            numeric_value: 4,
        };

        let ctx = MCTPSMBusContextRequest::new(DEST_ID);
        let mut buf: [u8; 21] = [0; 21];

        let len = ctx
            .vendor_defined(0xB, &VENDOR_ID, &[0x00, 0x01, 0x00], &mut buf)
            .unwrap();

        println!("buf: {:#x?}", buf);

        assert_eq!(len, 15);
        // Byte count
        assert_eq!(buf[2], 11);
        // IC and Message Type
        assert_eq!(buf[8], 0 << 7 | MessageType::VendorDefinedPCI as u8);
        // PCIe Vendor ID
        assert_eq!(buf[9], 0x14);
        assert_eq!(buf[10], 0x14);
        // Payload
        assert_eq!(buf[11], 0x00);
        assert_eq!(buf[12], 0x01);
        assert_eq!(buf[13], 0x00);

        // PEC
        assert_eq!(buf[14], 0x5B);
    }
}
