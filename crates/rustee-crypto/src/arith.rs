//! GPD_SPE_010 ch.8 math. No TEE_* names. maxBigIntSize = 4096.
//! Layout: [0]=flags (bit0=neg), [1]=nlimbs, [2..]=little-endian limbs.

use alloc::vec::Vec;

pub const MAX_BIGINT_BITS: u32 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithError {
    BadSize,
    ShortBuffer,
}

const FLAG_NEG: u32 = 1;

pub const fn bigint_size_in_u32(nbits: u32) -> usize {
    ((nbits as usize + 31) / 32) + 2
}

pub fn fmm_context_size_in_u32(modulus_bits: usize) -> usize {
    bigint_size_in_u32(modulus_bits as u32) + 4
}

pub fn fmm_size_in_u32(modulus_bits: usize) -> usize {
    bigint_size_in_u32(modulus_bits as u32)
}

fn cap(op: &[u32]) -> Result<usize, ArithError> {
    if op.len() < 2 {
        return Err(ArithError::BadSize);
    }
    Ok(op.len() - 2)
}

fn nlimbs(op: &[u32]) -> Result<usize, ArithError> {
    cap(op)?;
    let n = op[1] as usize;
    if 2 + n > op.len() {
        return Err(ArithError::BadSize);
    }
    Ok(n)
}

fn limbs(op: &[u32]) -> Result<&[u32], ArithError> {
    let n = nlimbs(op)?;
    Ok(&op[2..2 + n])
}

fn trim(op: &mut [u32]) {
    let mut n = op[1] as usize;
    while n > 0 && op[1 + n] == 0 {
        n -= 1;
    }
    op[1] = n as u32;
    if n == 0 {
        op[0] = 0;
    }
}

pub fn init(op: &mut [u32], _nbits: usize) {
    for w in op.iter_mut() {
        *w = 0;
    }
}

pub fn init_fmm_context1(ctx: &mut [u32], modulus: &[u32]) {
    for w in ctx.iter_mut() {
        *w = 0;
    }
    let n = core::cmp::min(modulus.len(), ctx.len());
    ctx[..n].copy_from_slice(&modulus[..n]);
}

pub fn init_fmm(op: &mut [u32], nbits: usize) {
    init(op, nbits);
}

pub fn from_s32(op: &mut [u32], v: i32) {
    init(op, 32);
    if v == 0 {
        return;
    }
    if v < 0 {
        op[0] = FLAG_NEG;
        op[1] = 1;
        op[2] = (v.unsigned_abs()) as u32;
    } else {
        op[1] = 1;
        op[2] = v as u32;
    }
}

pub fn to_s32(op: &[u32]) -> Result<i32, ArithError> {
    let n = nlimbs(op)?;
    if n == 0 {
        return Ok(0);
    }
    if n > 1 || (n == 1 && op[2] > i32::MAX as u32) {
        return Err(ArithError::BadSize);
    }
    let mag = op[2] as i32;
    Ok(if op[0] & FLAG_NEG != 0 { -mag } else { mag })
}

pub fn from_octet_string(op: &mut [u32], buf: &[u8], sign: i32) -> Result<(), ArithError> {
    init(op, buf.len() * 8);
    if buf.is_empty() {
        return Ok(());
    }
    let mut bytes = buf.to_vec();
    bytes.reverse(); // to little-endian bytes
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
    let n = bytes.len() / 4;
    if n > cap(op)? {
        return Err(ArithError::BadSize);
    }
    for i in 0..n {
        op[2 + i] = u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
    }
    op[1] = n as u32;
    if sign < 0 {
        op[0] = FLAG_NEG;
    }
    trim(op);
    Ok(())
}

pub fn to_octet_string(op: &[u32], buf: &mut [u8]) -> Result<usize, ArithError> {
    let ls = limbs(op)?;
    if ls.is_empty() {
        return Ok(0);
    }
    let mut bytes = Vec::new();
    for w in ls {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    while bytes.last() == Some(&0) && bytes.len() > 1 {
        bytes.pop();
    }
    bytes.reverse();
    if buf.len() < bytes.len() {
        return Err(ArithError::ShortBuffer);
    }
    buf[..bytes.len()].copy_from_slice(&bytes);
    Ok(bytes.len())
}

pub fn cmp(a: &[u32], b: &[u32]) -> i32 {
    let sa = a.first().copied().unwrap_or(0) & FLAG_NEG;
    let sb = b.first().copied().unwrap_or(0) & FLAG_NEG;
    if sa != 0 && sb == 0 {
        return -1;
    }
    if sa == 0 && sb != 0 {
        return 1;
    }
    let mag = cmp_mag(a, b);
    if sa != 0 {
        -mag
    } else {
        mag
    }
}

fn cmp_mag(a: &[u32], b: &[u32]) -> i32 {
    let la = nlimbs(a).unwrap_or(0);
    let lb = nlimbs(b).unwrap_or(0);
    if la > lb {
        return 1;
    }
    if la < lb {
        return -1;
    }
    for i in (0..la).rev() {
        let x = a[2 + i];
        let y = b[2 + i];
        if x > y {
            return 1;
        }
        if x < y {
            return -1;
        }
    }
    0
}

pub fn cmp_s32(a: &[u32], b: i32) -> i32 {
    let mut tmp = [0u32; 4];
    from_s32(&mut tmp, b);
    cmp(a, &tmp)
}

pub fn assign(dest: &mut [u32], src: &[u32]) {
    let n = core::cmp::min(dest.len(), src.len());
    dest[..n].copy_from_slice(&src[..n]);
    for w in dest.iter_mut().skip(n) {
        *w = 0;
    }
}

pub fn abs(dest: &mut [u32], src: &[u32]) {
    assign(dest, src);
    dest[0] &= !FLAG_NEG;
}

pub fn neg(dest: &mut [u32], op: &[u32]) {
    assign(dest, op);
    if nlimbs(dest).unwrap_or(0) == 0 {
        dest[0] = 0;
        return;
    }
    dest[0] ^= FLAG_NEG;
}

pub fn get_bit(src: &[u32], bit: u32) -> bool {
    let i = (bit / 32) as usize;
    let n = nlimbs(src).unwrap_or(0);
    if i >= n {
        return false;
    }
    (src[2 + i] >> (bit % 32)) & 1 == 1
}

pub fn get_bit_count(src: &[u32]) -> usize {
    let ls = limbs(src).unwrap_or(&[]);
    if ls.is_empty() {
        return 0;
    }
    let last = *ls.last().unwrap();
    (ls.len() - 1) * 32 + (32 - last.leading_zeros() as usize)
}

pub fn set_bit(op: &mut [u32], bit: u32, val: bool) {
    let i = (bit / 32) as usize;
    if 2 + i >= op.len() {
        return;
    }
    if val {
        op[2 + i] |= 1 << (bit % 32);
        if (i as u32) + 1 > op[1] {
            op[1] = i as u32 + 1;
        }
    } else if i < nlimbs(op).unwrap_or(0) {
        op[2 + i] &= !(1 << (bit % 32));
        trim(op);
    }
}

pub fn shift_right(dest: &mut [u32], src: &[u32], bits: usize) {
    assign(dest, src);
    if bits == 0 {
        return;
    }
    let words = bits / 32;
    let rem = bits % 32;
    let n = nlimbs(dest).unwrap_or(0);
    if words >= n {
        init(dest, 0);
        return;
    }
    dest.copy_within(2 + words..2 + n, 2);
    let new_n = n - words;
    dest[1] = new_n as u32;
    if rem > 0 {
        let mut carry = 0u32;
        for i in (0..new_n).rev() {
            let cur = dest[2 + i];
            dest[2 + i] = (cur >> rem) | carry;
            carry = cur << (32 - rem);
        }
    }
    for w in dest.iter_mut().skip(2 + new_n) {
        *w = 0;
    }
    trim(dest);
}

fn add_mag(dest: &mut [u32], a: &[u32], b: &[u32]) -> Result<(), ArithError> {
    let la = nlimbs(a)?;
    let lb = nlimbs(b)?;
    let n = core::cmp::max(la, lb);
    if n + 1 > cap(dest)? {
        return Err(ArithError::BadSize);
    }
    let mut carry = 0u64;
    for i in 0..n {
        let x = if i < la { a[2 + i] as u64 } else { 0 };
        let y = if i < lb { b[2 + i] as u64 } else { 0 };
        let s = x + y + carry;
        dest[2 + i] = s as u32;
        carry = s >> 32;
    }
    dest[2 + n] = carry as u32;
    dest[1] = (n + if carry != 0 { 1 } else { 0 }) as u32;
    dest[0] = 0;
    Ok(())
}

fn sub_mag(dest: &mut [u32], a: &[u32], b: &[u32]) -> Result<(), ArithError> {
    // |a| >= |b|
    let la = nlimbs(a)?;
    let lb = nlimbs(b)?;
    let mut borrow = 0i64;
    for i in 0..la {
        let x = a[2 + i] as i64;
        let y = if i < lb { b[2 + i] as i64 } else { 0 };
        let mut d = x - y - borrow;
        if d < 0 {
            d += 1i64 << 32;
            borrow = 1;
        } else {
            borrow = 0;
        }
        dest[2 + i] = d as u32;
    }
    dest[1] = la as u32;
    dest[0] = 0;
    trim(dest);
    Ok(())
}

pub fn add(dest: &mut [u32], op1: &[u32], op2: &[u32]) {
    let s1 = op1.first().copied().unwrap_or(0) & FLAG_NEG;
    let s2 = op2.first().copied().unwrap_or(0) & FLAG_NEG;
    if s1 == s2 {
        let _ = add_mag(dest, op1, op2);
        dest[0] = s1;
        if nlimbs(dest).unwrap_or(0) == 0 {
            dest[0] = 0;
        }
    } else {
        match cmp_mag(op1, op2) {
            0 => init(dest, 0),
            1 => {
                let _ = sub_mag(dest, op1, op2);
                dest[0] = s1;
            }
            _ => {
                let _ = sub_mag(dest, op2, op1);
                dest[0] = s2;
            }
        }
    }
}

pub fn sub(dest: &mut [u32], op1: &[u32], op2: &[u32]) {
    let mut neg = [0u32; 130];
    assign(&mut neg, op2);
    if nlimbs(&neg).unwrap_or(0) != 0 {
        neg[0] ^= FLAG_NEG;
    }
    add(dest, op1, &neg);
}

pub fn mul(dest: &mut [u32], op1: &[u32], op2: &[u32]) {
    let la = nlimbs(op1).unwrap_or(0);
    let lb = nlimbs(op2).unwrap_or(0);
    let mut tmp = alloc::vec![0u32; 2 + la + lb + 1];
    for i in 0..la {
        let mut carry = 0u64;
        for j in 0..lb {
            let idx = 2 + i + j;
            let p = tmp[idx] as u64 + op1[2 + i] as u64 * op2[2 + j] as u64 + carry;
            tmp[idx] = p as u32;
            carry = p >> 32;
        }
        tmp[2 + i + lb] = carry as u32;
    }
    tmp[1] = (la + lb) as u32;
    tmp[0] = (op1.first().copied().unwrap_or(0) ^ op2.first().copied().unwrap_or(0)) & FLAG_NEG;
    trim(&mut tmp);
    assign(dest, &tmp);
}

pub fn square(dest: &mut [u32], op: &[u32]) {
    mul(dest, op, op);
}

fn is_zero(op: &[u32]) -> bool {
    nlimbs(op).unwrap_or(0) == 0
}

pub fn div(quot: &mut [u32], rem: &mut [u32], op1: &[u32], op2: &[u32]) {
    // restoring division on magnitudes; signs: quot sign = xor, rem sign = dividend
    if is_zero(op2) {
        init(quot, 0);
        init(rem, 0);
        return;
    }
    init(quot, 0);
    assign(rem, op1);
    rem[0] = 0;
    let mut dvs = [0u32; 130];
    assign(&mut dvs, op2);
    dvs[0] = 0;
    if cmp_mag(rem, &dvs) < 0 {
        rem[0] = op1.first().copied().unwrap_or(0) & FLAG_NEG;
        return;
    }
    let bits = get_bit_count(rem).saturating_sub(get_bit_count(&dvs)) + 1;
    for i in (0..bits).rev() {
        let mut shifted = [0u32; 130];
        // dvs << i
        assign(&mut shifted, &dvs);
        shl_words(&mut shifted, i);
        if cmp_mag(rem, &shifted) >= 0 {
            let mut nrem = [0u32; 130];
            let _ = sub_mag(&mut nrem, rem, &shifted);
            assign(rem, &nrem);
            set_bit(quot, i as u32, true);
        }
    }
    quot[0] = (op1.first().copied().unwrap_or(0) ^ op2.first().copied().unwrap_or(0)) & FLAG_NEG;
    rem[0] = op1.first().copied().unwrap_or(0) & FLAG_NEG;
    trim(quot);
    trim(rem);
}

fn shl_words(op: &mut [u32], bits: usize) {
    if bits == 0 || is_zero(op) {
        return;
    }
    let words = bits / 32;
    let rem = bits % 32;
    let n = nlimbs(op).unwrap_or(0);
    if 2 + n + words + 1 > op.len() {
        return;
    }
    if words > 0 {
        for i in (0..n).rev() {
            op[2 + i + words] = op[2 + i];
        }
        for i in 0..words {
            op[2 + i] = 0;
        }
        op[1] = (n + words) as u32;
    }
    if rem > 0 {
        let n = nlimbs(op).unwrap_or(0);
        let mut carry = 0u32;
        for i in 0..n {
            let cur = op[2 + i];
            op[2 + i] = (cur << rem) | carry;
            carry = cur >> (32 - rem);
        }
        if carry != 0 && 2 + n < op.len() {
            op[2 + n] = carry;
            op[1] = (n + 1) as u32;
        }
    }
}

pub fn modulo(dest: &mut [u32], op: &[u32], n: &[u32]) {
    let mut q = [0u32; 130];
    div(&mut q, dest, op, n);
    dest[0] = 0; // GP modulo is non-negative remainder typically
    if (op.first().copied().unwrap_or(0) & FLAG_NEG) != 0 && !is_zero(dest) {
        let mut t = [0u32; 130];
        sub(&mut t, n, dest);
        assign(dest, &t);
        dest[0] = 0;
    }
}

pub fn add_mod(dest: &mut [u32], op1: &[u32], op2: &[u32], n: &[u32]) {
    let mut s = [0u32; 130];
    add(&mut s, op1, op2);
    modulo(dest, &s, n);
}

pub fn sub_mod(dest: &mut [u32], op1: &[u32], op2: &[u32], n: &[u32]) {
    let mut s = [0u32; 130];
    sub(&mut s, op1, op2);
    modulo(dest, &s, n);
}

pub fn mul_mod(dest: &mut [u32], op1: &[u32], op2: &[u32], n: &[u32]) {
    let mut s = [0u32; 260];
    mul(&mut s, op1, op2);
    modulo(dest, &s, n);
}

pub fn square_mod(dest: &mut [u32], op: &[u32], n: &[u32]) {
    mul_mod(dest, op, op, n);
}

pub fn inv_mod(dest: &mut [u32], op: &[u32], n: &[u32]) {
    let mut g = [0u32; 130];
    let mut u = [0u32; 130];
    let mut v = [0u32; 130];
    compute_extended_gcd(&mut g, &mut u, &mut v, op, n);
    let mut one = [0u32; 4];
    from_s32(&mut one, 1);
    if cmp(&g, &one) != 0 {
        init(dest, 0);
        return;
    }
    modulo(dest, &u, n);
}

pub fn exp_mod(dest: &mut [u32], op: &[u32], exp: &[u32], n: &[u32], _ctx: Option<&[u32]>) {
    let mut base = [0u32; 130];
    modulo(&mut base, op, n);
    let mut result = [0u32; 130];
    from_s32(&mut result, 1);
    let bits = get_bit_count(exp);
    for i in 0..bits {
        if get_bit(exp, i as u32) {
            let mut t = [0u32; 130];
            mul_mod(&mut t, &result, &base, n);
            assign(&mut result, &t);
        }
        let mut sq = [0u32; 130];
        square_mod(&mut sq, &base, n);
        assign(&mut base, &sq);
    }
    assign(dest, &result);
}

pub fn relative_prime(op1: &[u32], op2: &[u32]) -> bool {
    let mut g = [0u32; 130];
    let mut u = [0u32; 130];
    let mut v = [0u32; 130];
    compute_extended_gcd(&mut g, &mut u, &mut v, op1, op2);
    let mut one = [0u32; 4];
    from_s32(&mut one, 1);
    cmp(&g, &one) == 0
}

pub fn compute_extended_gcd(
    gcd: &mut [u32],
    u: &mut [u32],
    v: &mut [u32],
    op1: &[u32],
    op2: &[u32],
) {
    // iterative EGCD
    let mut r0 = [0u32; 130];
    let mut r1 = [0u32; 130];
    assign(&mut r0, op1);
    r0[0] = 0;
    assign(&mut r1, op2);
    r1[0] = 0;
    let mut s0 = [0u32; 130];
    let mut s1 = [0u32; 130];
    let mut t0 = [0u32; 130];
    let mut t1 = [0u32; 130];
    from_s32(&mut s0, 1);
    from_s32(&mut t1, 1);
    while !is_zero(&r1) {
        let mut q = [0u32; 130];
        let mut r = [0u32; 130];
        div(&mut q, &mut r, &r0, &r1);
        assign(&mut r0, &r1);
        assign(&mut r1, &r);
        let mut tmp = [0u32; 130];
        mul(&mut tmp, &q, &s1);
        let mut ns = [0u32; 130];
        sub(&mut ns, &s0, &tmp);
        assign(&mut s0, &s1);
        assign(&mut s1, &ns);
        mul(&mut tmp, &q, &t1);
        let mut nt = [0u32; 130];
        sub(&mut nt, &t0, &tmp);
        assign(&mut t0, &t1);
        assign(&mut t1, &nt);
    }
    assign(gcd, &r0);
    assign(u, &s0);
    assign(v, &t0);
}

pub fn is_probable_prime(op: &[u32], confidence: u32) -> i32 {
    if (op.first().copied().unwrap_or(0) & FLAG_NEG) != 0 {
        return 0;
    }
    if is_zero(op) {
        return 0;
    }
    let mut two = [0u32; 4];
    from_s32(&mut two, 2);
    if cmp(op, &two) < 0 {
        return 0;
    }
    if cmp(op, &two) == 0 {
        return 1;
    }
    if !get_bit(op, 0) {
        return 0;
    }
    // deterministic witnesses for 32-bit; for larger, a few Miller-Rabin rounds
    let rounds = core::cmp::max(1, core::cmp::min(confidence, 8));
    let mut n1 = [0u32; 130];
    let mut one = [0u32; 4];
    from_s32(&mut one, 1);
    sub(&mut n1, op, &one);
    for r in 0..rounds {
        let mut a = [0u32; 4];
        from_s32(&mut a, 2 + r as i32);
        if cmp_mag(&a, op) >= 0 {
            break;
        }
        let mut x = [0u32; 130];
        exp_mod(&mut x, &a, &n1, op, None);
        if cmp(&x, &one) != 0 {
            return 0;
        }
    }
    1
}

pub fn convert_to_fmm(dest: &mut [u32], src: &[u32], n: &[u32], _ctx: &[u32]) {
    modulo(dest, src, n);
}

pub fn convert_from_fmm(dest: &mut [u32], src: &[u32], n: &[u32], _ctx: &[u32]) {
    modulo(dest, src, n);
}

pub fn compute_fmm(dest: &mut [u32], op1: &[u32], op2: &[u32], n: &[u32], _ctx: &[u32]) {
    mul_mod(dest, op1, op2, n);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_mul_mod() {
        let mut a = [0u32; 8];
        let mut b = [0u32; 8];
        from_s32(&mut a, 21);
        from_s32(&mut b, 21);
        let mut c = [0u32; 8];
        add(&mut c, &a, &b);
        assert_eq!(to_s32(&c).unwrap(), 42);
        mul(&mut c, &a, &b);
        assert_eq!(to_s32(&c).unwrap(), 441);
        let mut n = [0u32; 8];
        from_s32(&mut n, 100);
        let mut m = [0u32; 8];
        modulo(&mut m, &c, &n);
        assert_eq!(to_s32(&m).unwrap(), 41);
        assert_eq!(bigint_size_in_u32(4096), 130);
    }
}
