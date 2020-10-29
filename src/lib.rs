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

#![no_std]
#![deny(missing_docs)]

#[macro_use]
extern crate bitfield;

pub mod base_packet;
pub mod control_packet;
pub mod mctp_traits;
pub mod smbus;
pub mod smbus_raw;

#[cfg(test)]
#[macro_use]
extern crate std;
