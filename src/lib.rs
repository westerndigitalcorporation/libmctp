//! libMCTP is a MCTP (Management Component Transport Protocol) implementation
//! for Rust.
//!
//! libMCTP aims to implement the MCTP protocol as described in the DMTF DSP2016
//! specification, which can be found here:
//! https://www.dmtf.org/sites/default/files/standards/documents/DSP2016.pdf
//!
//! MCTP allows multiple transport layers, the protocols supported by this library
//! include:
//!  * SMBus/I2C version 1.2.0. See DMTF DSP0237 (https://www.dmtf.org/sites/default/files/standards/documents/DSP0237_1.2.0.pdf)
//!
//! libMCTP does not send or receive any data. Instead it generates u8 arrays
//! that contain all of the bytes that should be sent or decodes u8 arrays.
//! This allows you to use your own SMBus/I2C implementation.
//!

#![no_std]
#![deny(missing_docs)]

#[macro_use]
extern crate bitfield;

pub mod base_packet;
pub mod control_packet;
pub mod errors;
/// Internal MCTP traits.
mod mctp_traits;
pub mod smbus;
pub mod smbus_proto;
pub mod smbus_request;
pub mod smbus_response;

// Use this to generate nicer docs
#[doc(inline)]
pub use crate::base_packet::MessageType;
#[doc(inline)]
pub use crate::control_packet::MCTPControlMessageHeader;
#[doc(inline)]
pub use crate::smbus::MCTPSMBusContext;
#[doc(inline)]
pub use crate::smbus_request::MCTPSMBusContextRequest;
#[doc(inline)]
pub use crate::smbus_response::MCTPSMBusContextResponse;

// This is used to run the tests on a host
#[cfg(test)]
#[macro_use]
extern crate std;
