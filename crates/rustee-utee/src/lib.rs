#![no_std]
//! Independently written GPD_SPE_010 v1.3.1 identifiers. Not copied from OP-TEE or GP PDFs.
//!
//! TCF + Time + properties + Internal Client API. Crypto/storage/arith are declared
//! or thin-forwarded. TAs must not link rustee-os.

extern crate alloc;

pub type TeeResult = u32;
pub const TEE_SUCCESS: TeeResult = 0;
pub const TEE_ERROR_CORRUPT_OBJECT: TeeResult = 0xF0100001;
pub const TEE_ERROR_CORRUPT_OBJECT_2: TeeResult = 0xF0100002;
pub const TEE_ERROR_STORAGE_NOT_AVAILABLE: TeeResult = 0xF0100003;
pub const TEE_ERROR_STORAGE_NOT_AVAILABLE_2: TeeResult = 0xF0100004;
pub const TEE_ERROR_UNSUPPORTED_VERSION: TeeResult = 0xF0100005;
pub const TEE_ERROR_CIPHERTEXT_INVALID: TeeResult = 0xF0100006;
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
pub const TEE_ERROR_EXTERNAL_CANCEL: TeeResult = 0xFFFF0011;
pub const TEE_ERROR_TIMEOUT: TeeResult = 0xFFFF3001;
pub const TEE_ERROR_OVERFLOW: TeeResult = 0xFFFF300F;
pub const TEE_ERROR_TARGET_DEAD: TeeResult = 0xFFFF3024;
pub const TEE_ERROR_STORAGE_NO_SPACE: TeeResult = 0xFFFF3041;
pub const TEE_ERROR_MAC_INVALID: TeeResult = 0xFFFF3071;
pub const TEE_ERROR_SIGNATURE_INVALID: TeeResult = 0xFFFF3072;
pub const TEE_ERROR_TIME_NOT_SET: TeeResult = 0xFFFF5000;
pub const TEE_ERROR_TIME_NEEDS_RESET: TeeResult = 0xFFFF5001;

pub const TEE_ORIGIN_API: u32 = 1;
pub const TEE_ORIGIN_COMMS: u32 = 2;
pub const TEE_ORIGIN_TEE: u32 = 3;
pub const TEE_ORIGIN_TRUSTED_APP: u32 = 4;

/// Local define; spec uses a literal 4 via paramTypes.
pub const TEE_NUM_PARAMS: usize = 4;

pub const TEE_PARAM_TYPE_NONE: u32 = 0;
pub const TEE_PARAM_TYPE_VALUE_INPUT: u32 = 1;
pub const TEE_PARAM_TYPE_VALUE_OUTPUT: u32 = 2;
pub const TEE_PARAM_TYPE_VALUE_INOUT: u32 = 3;
pub const TEE_PARAM_TYPE_MEMREF_INPUT: u32 = 5;
pub const TEE_PARAM_TYPE_MEMREF_OUTPUT: u32 = 6;
pub const TEE_PARAM_TYPE_MEMREF_INOUT: u32 = 7;

pub const TEE_LOGIN_PUBLIC: u32 = 0x00000000;
pub const TEE_LOGIN_USER: u32 = 0x00000001;
pub const TEE_LOGIN_GROUP: u32 = 0x00000002;
pub const TEE_LOGIN_APPLICATION: u32 = 0x00000004;
pub const TEE_LOGIN_USER_APPLICATION: u32 = 0x00000005;
pub const TEE_LOGIN_GROUP_APPLICATION: u32 = 0x00000006;
pub const TEE_LOGIN_TRUSTED_APP: u32 = 0xF0000000;

pub const TEE_HANDLE_NULL: usize = 0;
pub const TEE_TIMEOUT_INFINITE: u32 = 0xFFFF_FFFF;

pub const TEE_MALLOC_FILL_ZERO: u32 = 0;
pub const TEE_MALLOC_NO_FILL: u32 = 1;
pub const TEE_MALLOC_NO_SHARE: u32 = 2;

pub mod arith;
pub mod c_abi;
pub mod client;
pub mod crypto_api;
pub mod header;
pub mod kernel_abi;
pub mod mem;
pub mod panic_api;
pub mod param;
pub mod property;
pub mod runtime;
pub mod ta;
pub mod time_api;

pub use kernel_abi::{
    Dir, KernelCmd, KernelOut, Login, Param, SessionId, TeeSyscall, Uuid, param_from_gp,
    param_types,
};
pub use param::{Identity, Params, TeeParam, TeeTime, TeeUuid};
pub use runtime::{Entropy, TimeSource, with_entropy, with_syscall, with_time};
pub use ta::Ta;

#[cfg(test)]
mod tests;
