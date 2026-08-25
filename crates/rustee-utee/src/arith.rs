//! Arith stubs. rustee-crypto `arith` is empty on main; do not call it.
//! Init zeros the TA buffer locally.

use crate::{TEE_ERROR_NOT_IMPLEMENTED, TeeResult};

pub fn big_int_init(big_int: *mut u32, len: usize) {
    if big_int.is_null() || len == 0 {
        return;
    }
    unsafe { core::ptr::write_bytes(big_int, 0, len) };
}

pub fn big_int_fmm_size_in_u32(_modulus_size_in_bits: usize) -> usize {
    0
}

pub fn big_int_fmm_context_size_in_u32(_modulus_size_in_bits: usize) -> usize {
    0
}

pub fn big_int_init_fmm_context1(
    _context: *mut u32,
    _len: usize,
    _modulus: *const u32,
) -> TeeResult {
    TEE_ERROR_NOT_IMPLEMENTED
}

pub fn big_int_init_fmm_context(context: *mut u32, len: usize, modulus: *const u32) {
    let _ = big_int_init_fmm_context1(context, len, modulus);
}

pub fn big_int_init_fmm(big_int_fmm: *mut u32, len: usize) {
    big_int_init(big_int_fmm, len);
}
