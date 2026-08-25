#![no_std]
//! Independently written GPD_SPE_010 v1.3.1 identifiers. Not copied from OP-TEE or GP PDFs.

pub type TeeResult = u32;
pub const TEE_SUCCESS: TeeResult = 0;
pub const TEE_ERROR_GENERIC: TeeResult = 0xFFFF0000;
pub const TEE_ERROR_ACCESS_DENIED: TeeResult = 0xFFFF0001;
pub const TEE_ERROR_CANCEL: TeeResult = 0xFFFF0002;
pub const TEE_ERROR_ACCESS_CONFLICT: TeeResult = 0xFFFF0003;
pub const TEE_ERROR_EXCESS_DATA: TeeResult = 0xFFFF0004;
pub const TEE_ERROR_BAD_FORMAT: TeeResult = 0xFFFF0005;
pub const TEE_ERROR_BAD_PARAMETERS: TeeResult = 0xFFFF0006;
pub const TEE_ERROR_BAD_STATE: TeeResult = 0xFFFF0007;
pub const TEE_ERROR_ITEM_NOT_FOUND: TeeResult = 0xFFFF0008;
pub const TEE_ERROR_NOT_IMPLEMENTED: TeeResult = 0xFFFF0009;
pub const TEE_ERROR_NOT_SUPPORTED: TeeResult = 0xFFFF000A;
pub const TEE_ERROR_NO_DATA: TeeResult = 0xFFFF000B;
pub const TEE_ERROR_OUT_OF_MEMORY: TeeResult = 0xFFFF000C;
pub const TEE_ERROR_BUSY: TeeResult = 0xFFFF000D;
pub const TEE_ERROR_COMMUNICATION: TeeResult = 0xFFFF000E;
pub const TEE_ERROR_SECURITY: TeeResult = 0xFFFF000F;
pub const TEE_ERROR_SHORT_BUFFER: TeeResult = 0xFFFF0010;
pub const TEE_ERROR_TIMEOUT: TeeResult = 0xFFFF3001;
pub const TEE_ERROR_OVERFLOW: TeeResult = 0xFFFF300F;
pub const TEE_ERROR_TARGET_DEAD: TeeResult = 0xFFFF3024;
pub const TEE_ERROR_STORAGE_NO_SPACE: TeeResult = 0xFFFF3041;
pub const TEE_ERROR_TIME_NOT_SET: TeeResult = 0xFFFF5000;
pub const TEE_ERROR_TIME_NEEDS_RESET: TeeResult = 0xFFFF5001;

pub const TEE_ORIGIN_API: u32 = 1;
pub const TEE_ORIGIN_COMMS: u32 = 2;
pub const TEE_ORIGIN_TEE: u32 = 3;
pub const TEE_ORIGIN_TRUSTED_APP: u32 = 4;

/// Local define; spec uses a literal 4 via paramTypes.
pub const TEE_NUM_PARAMS: usize = 4;

#[cfg(test)]
mod tests {
    #[test]
    fn success_is_zero() {
        assert_eq!(super::TEE_SUCCESS, 0);
        assert_eq!(super::TEE_ERROR_NOT_SUPPORTED, 0xFFFF000A);
        assert_eq!(super::TEE_ERROR_TARGET_DEAD, 0xFFFF3024);
    }
}
