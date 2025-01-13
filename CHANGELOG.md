# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-01-13

### Added

- Support for PCI Vendor messages
- Support for IANA Vendor messages
- Support for SpdmOverMctp and SecuredMessages message types
- Expose SMBusMCTPRequestResponse struct
- Check in Cargo.lock

### Changed

- Vendor formats (like VendorIDFormat) are now in the `libmctp::vendor_packets` crate
- generate_packet_bytes() was renamed to generate_control_packet_bytes()
- Switched to 2021 edition of Rust
- Updated package dependencies
