//! Thin-forward GPD_SPE_010 ch.8 math onto `rustee_crypto::arith`.
//! No local SHALL table. Layout is crypto's: 2 uint32 metadata + limbs.
//! Pass the whole TA allocation; do not parse metadata here.

use crate::panic_api::tee_panic;
use crate::{TEE_ERROR_BAD_PARAMETERS, TEE_ERROR_SHORT_BUFFER, TEE_SUCCESS, TeeResult};
use rustee_crypto::arith::{self as crypto_arith, ArithError};

fn bad_size() -> ! {
    tee_panic(TEE_ERROR_BAD_PARAMETERS);
}

fn require_len(op: &[u32], min: usize) {
    if op.len() < min {
        bad_size();
    }
}

fn dest_slice<'a>(p: *mut u32, len: usize) -> &'a mut [u32] {
    if p.is_null() || len < 2 {
        bad_size();
    }
    unsafe { core::slice::from_raw_parts_mut(p, len) }
}

/// Source BigInt: whole initialized value (metadata + nlimbs). Capacity is not
/// stored in the buffer; nlimbs recovers the used width without extracting limbs
/// for math.
fn src_slice<'a>(p: *const u32) -> &'a [u32] {
    if p.is_null() {
        bad_size();
    }
    let nlimbs = unsafe { *p.add(1) } as usize;
    let words = nlimbs.saturating_add(2);
    let max = crypto_arith::bigint_size_in_u32(crypto_arith::MAX_BIGINT_BITS);
    if words > max || words < 2 {
        bad_size();
    }
    unsafe { core::slice::from_raw_parts(p, words) }
}

fn map_arith(e: ArithError) -> TeeResult {
    match e {
        ArithError::ShortBuffer => TEE_ERROR_SHORT_BUFFER,
        ArithError::BadSize => bad_size(),
    }
}

pub fn fmm_size_in_u32(modulus_size_in_bits: usize) -> usize {
    crypto_arith::fmm_size_in_u32(modulus_size_in_bits)
}

pub fn fmm_context_size_in_u32(modulus_size_in_bits: usize) -> usize {
    crypto_arith::fmm_context_size_in_u32(modulus_size_in_bits)
}

pub fn init(op: &mut [u32]) {
    require_len(op, 2);
    let nbits = (op.len() - 2).saturating_mul(32);
    crypto_arith::init(op, nbits);
}

pub fn init_fmm(op: &mut [u32]) {
    require_len(op, 2);
    let nbits = (op.len() - 2).saturating_mul(32);
    crypto_arith::init_fmm(op, nbits);
}

pub fn init_fmm_context1(ctx: &mut [u32], modulus: &[u32]) {
    require_len(ctx, 2);
    require_len(modulus, 2);
    crypto_arith::init_fmm_context1(ctx, modulus);
}

pub fn from_s32(op: &mut [u32], v: i32) {
    require_len(op, 3);
    crypto_arith::from_s32(op, v);
}

pub fn to_s32(op: &[u32]) -> i32 {
    require_len(op, 2);
    match crypto_arith::to_s32(op) {
        Ok(v) => v,
        Err(e) => {
            map_arith(e);
            bad_size();
        }
    }
}

pub fn add(dest: &mut [u32], op1: &[u32], op2: &[u32]) {
    require_len(dest, 2);
    require_len(op1, 2);
    require_len(op2, 2);
    crypto_arith::add(dest, op1, op2);
}

pub fn sub(dest: &mut [u32], op1: &[u32], op2: &[u32]) {
    require_len(dest, 2);
    require_len(op1, 2);
    require_len(op2, 2);
    crypto_arith::sub(dest, op1, op2);
}

pub fn mul(dest: &mut [u32], op1: &[u32], op2: &[u32]) {
    require_len(dest, 2);
    require_len(op1, 2);
    require_len(op2, 2);
    crypto_arith::mul(dest, op1, op2);
}

pub fn cmp(op1: &[u32], op2: &[u32]) -> i32 {
    require_len(op1, 2);
    require_len(op2, 2);
    crypto_arith::cmp(op1, op2)
}

pub fn assign(dest: &mut [u32], src: &[u32]) {
    require_len(dest, 2);
    require_len(src, 2);
    crypto_arith::assign(dest, src);
}

pub fn modulo(dest: &mut [u32], op: &[u32], n: &[u32]) {
    require_len(dest, 2);
    require_len(op, 2);
    require_len(n, 2);
    crypto_arith::modulo(dest, op, n);
}

pub fn from_octet_string(op: &mut [u32], buf: &[u8], sign: i32) -> TeeResult {
    require_len(op, 2);
    match crypto_arith::from_octet_string(op, buf, sign) {
        Ok(()) => TEE_SUCCESS,
        Err(e) => map_arith(e),
    }
}

pub fn to_octet_string(op: &[u32], buf: &mut [u8]) -> Result<usize, TeeResult> {
    require_len(op, 2);
    match crypto_arith::to_octet_string(op, buf) {
        Ok(n) => Ok(n),
        Err(e) => Err(map_arith(e)),
    }
}

pub fn big_int_fmm_size_in_u32(modulus_size_in_bits: usize) -> usize {
    fmm_size_in_u32(modulus_size_in_bits)
}

pub fn big_int_fmm_context_size_in_u32(modulus_size_in_bits: usize) -> usize {
    fmm_context_size_in_u32(modulus_size_in_bits)
}

pub fn big_int_init(big_int: *mut u32, len: usize) {
    init(dest_slice(big_int, len));
}

pub fn big_int_init_fmm(big_int_fmm: *mut u32, len: usize) {
    init_fmm(dest_slice(big_int_fmm, len));
}

pub fn big_int_init_fmm_context1(
    context: *mut u32,
    len: usize,
    modulus: *const u32,
) -> TeeResult {
    init_fmm_context1(dest_slice(context, len), src_slice(modulus));
    TEE_SUCCESS
}

/// Deprecated alias of `init_fmm_context1`.
pub fn big_int_init_fmm_context(context: *mut u32, len: usize, modulus: *const u32) {
    let _ = big_int_init_fmm_context1(context, len, modulus);
}
