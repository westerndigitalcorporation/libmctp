//! The error types used by MCTP and libMCTP

#[derive(Debug)]
/// The possible Control Message errors
pub enum ControlMessageError {
    /// Unknown
    Unknown,
    /// The control request packet data length is invalid
    InvalidRequestDataLength,
}

#[derive(Debug)]
/// The possible errors when decoding a packet
pub enum DecodeError {
    /// Unknown error
    Unknown,
    /// There was a control message error
    ControlMessage(ControlMessageError),
}
