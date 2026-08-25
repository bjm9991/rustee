#![no_std]
//! REE-facing OP-TEE MSG compatibility shim. Internals are Rust types, not OP-TEE.
//! Do not copy Linux GPL headers (`optee_msg.h`).
//!
//! CALLS_UID (OP-TEE API UID): 384fb3e0-e7f8-11e3-af63-0002a5d5c51b
//! RUSTEE OS UUID: e819d7df-5ffe-45e6-a113-323349b219aa
//! GET_OS_REVISION: 0.1.0
//!
//! v0 vsock PDU (LE): u32 kind (ENTER=1, RPC=2, COMPLETE=3, RPC_REPLY=4),
//! seq, arg_len, bounce_len, then 64-byte CallFrame, then bounce.
//! MSG blob lives in the bounce pool at cookie a1:a2.

pub const CALLS_UID: [u8; 16] = [
    0x38, 0x4f, 0xb3, 0xe0, 0xe7, 0xf8, 0x11, 0xe3, 0xaf, 0x63, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b,
];
pub const OS_UUID: [u8; 16] = [
    0xe8, 0x19, 0xd7, 0xdf, 0x5f, 0xfe, 0x45, 0xe6, 0xa1, 0x13, 0x32, 0x33, 0x49, 0xb2, 0x19, 0xaa,
];
pub const OS_REVISION_MAJOR: u32 = 0;
pub const OS_REVISION_MINOR: u32 = 1;

pub const KIND_ENTER: u32 = 1;
pub const KIND_RPC: u32 = 2;
pub const KIND_COMPLETE: u32 = 3;
pub const KIND_RPC_REPLY: u32 = 4;

#[derive(Clone, Copy, Debug)]
pub struct OpteeMsgArgStub {
    pub cmd: u32,
    pub func: u32,
    pub session: u32,
}

#[cfg(test)]
mod tests {
    #[test]
    fn uuids_len() {
        assert_eq!(super::CALLS_UID.len(), 16);
        assert_eq!(super::OS_UUID.len(), 16);
    }
}
