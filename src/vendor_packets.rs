//! This describes the MCTP Vendor defined headers and protocols.
//!
//! The control packet is described in DSP0236, section 13.

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

bitfield! {
    /// This is the header for the Vendor Defined PCI message format
    pub struct PCIMessageFormat(MSB0 [u8]);
    u16;
    /// PCI/PCIe Vendor ID
    pub vendor_id, set_vendor_id : 15, 0;
}

impl PCIMessageFormat<[u8; 2]> {
    /// Create a new PCIMessageFormat.
    ///
    /// `vendor_id`: PCI/PCIe Vendor ID. Refer to PCIe. MSB first. This value
    /// is formatted per the Vendor Data Field for the PCI Express vendor
    /// ID format. See 12.8.1".
    pub fn new(vendor_id: u16) -> Self {
        let buf = [0; 2];
        let mut header = PCIMessageFormat(buf);

        header.set_vendor_id(vendor_id);

        header
    }

    /// Create a new `PCIMessageFormat` from an existing buffer.
    ///
    /// `buffer`: The existing buffer for the `PCIMessageFormat`
    /// No checks are performed on the `buffer`.
    pub fn new_from_buf(buf: [u8; 2]) -> Self {
        PCIMessageFormat(buf)
    }
}

bitfield! {
    /// This is the header for the Vendor Defined PCI message format
    pub struct IANAMessageFormat(MSB0 [u8]);
    u32;
    /// IANA Enterprise ID for Vendor
    pub vendor_id, set_vendor_id : 31, 0;
}

impl IANAMessageFormat<[u8; 4]> {
    /// Create a new PCIMessageFormat.
    ///
    /// `vendor_id`: PCI/PCIe Vendor ID. Refer to PCIe. MSB first. This value
    /// is formatted per the Vendor Data Field for the PCI Express vendor
    /// ID format. See 12.8.1".
    pub fn new(vendor_id: u32) -> Self {
        let buf = [0; 4];
        let mut header = IANAMessageFormat(buf);

        header.set_vendor_id(vendor_id);

        header
    }

    /// Create a new `IANAMessageFormat` from an existing buffer.
    ///
    /// `buffer`: The existing buffer for the `IANAMessageFormat`
    /// No checks are performed on the `buffer`.
    pub fn new_from_buf(buf: [u8; 4]) -> Self {
        IANAMessageFormat(buf)
    }
}
