//! The public error types used by libMCTP

use crate::control_packet::CompletionCode;

#[derive(Debug, PartialEq)]
/// The possible Control Message errors
pub enum ControlMessageError {
    /// Unknown
    Unknown,
    /// The control request packet data length is invalid
    InvalidRequestDataLength,
    /// The packet sent has an invalid control header
    InvalidControlHeader,
    ///
    UnsuccessfulCompletionCode(CompletionCode),
    /// Invalid PEC
    InvalidPEC,
}

#[derive(Debug, PartialEq)]
/// The possible errors when decoding a packet
pub enum DecodeError {
    /// Unknown error
    Unknown,
    /// There was a control message error
    ControlMessage(ControlMessageError),
}
