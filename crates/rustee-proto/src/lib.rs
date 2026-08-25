#![no_std]
//! REE-facing OP-TEE MSG compatibility shim. Kernel internals stay Rust types.
//! Independently written from the public MSG layout; do not copy Linux GPL headers.
//!
//! implements OP-TEE MSG 2.0 wire as used by stock tee.ko on tz-aarch64.
//! CALLS_UID stays the OP-TEE API UID so that decoder binds.
//! GET_OS_UUID is RUSTEE, never OP-TEE 486178e0.
//!
//! v0 virt vsock (Architect freeze):
//! PDU LE: kind, seq, arg_len, bounce_len, then 64-byte CallFrame, then bounce.
//! arg_len = 64 on ENTER/RPC/COMPLETE/RPC_REPLY. MSG is NOT in the vsock arg;
//! it lives in the bounce pool at cookie a1:a2 (a1 = high 32, a2 = low 32).

pub const CALLS_UID_WORDS: [u32; 4] = [0x384f_b3e0, 0xe7f8_11e3, 0xaf63_0002, 0xa5d5_c51b];
pub const OS_UUID_WORDS: [u32; 4] = [0xe819_d7df, 0x5ffe_45e6, 0xa113_3233, 0x49b2_19aa];
pub const OS_REVISION_MAJOR: u32 = 0;
pub const OS_REVISION_MINOR: u32 = 1;

pub const VSOCK_GUEST_CID: u32 = 3;
pub const VSOCK_PORT: u32 = 7007;
pub const BOUNCE_POOL_SIZE: usize = 16 * 1024 * 1024;
pub const PDU_HDR_LEN: usize = 16;
pub const CALL_FRAME_LEN: usize = 64;
pub const MSG_ARG_ALIGN: usize = 8;
pub const PAGE_SIZE: usize = 4096;

pub const KIND_ENTER: u32 = 1;
pub const KIND_RPC: u32 = 2;
pub const KIND_COMPLETE: u32 = 3;
pub const KIND_RPC_REPLY: u32 = 4;

pub const MSG_CMD_OPEN_SESSION: u32 = 0;
pub const MSG_CMD_INVOKE_COMMAND: u32 = 1;
pub const MSG_CMD_CLOSE_SESSION: u32 = 2;
pub const MSG_CMD_CANCEL: u32 = 3;
pub const MSG_CMD_REGISTER_SHM: u32 = 4;
pub const MSG_CMD_UNREGISTER_SHM: u32 = 5;

pub const ATTR_TYPE_NONE: u64 = 0x0;
pub const ATTR_TYPE_VALUE_INPUT: u64 = 0x1;
pub const ATTR_TYPE_VALUE_OUTPUT: u64 = 0x2;
pub const ATTR_TYPE_VALUE_INOUT: u64 = 0x3;
pub const ATTR_TYPE_RMEM_INPUT: u64 = 0x5;
pub const ATTR_TYPE_RMEM_OUTPUT: u64 = 0x6;
pub const ATTR_TYPE_RMEM_INOUT: u64 = 0x7;
pub const ATTR_TYPE_TMEM_INPUT: u64 = 0x9;
pub const ATTR_TYPE_TMEM_OUTPUT: u64 = 0xa;
pub const ATTR_TYPE_TMEM_INOUT: u64 = 0xb;
pub const ATTR_TYPE_MASK: u64 = 0xff;
pub const ATTR_META: u64 = 1 << 8;
pub const ATTR_NONCONTIG: u64 = 1 << 9;

pub const MSG_LOGIN_PUBLIC: u32 = 0;
pub const MSG_LOGIN_USER: u32 = 1;
pub const MSG_LOGIN_GROUP: u32 = 2;
pub const MSG_LOGIN_APPLICATION: u32 = 4;
pub const MSG_LOGIN_APPLICATION_USER: u32 = 5;
pub const MSG_LOGIN_APPLICATION_GROUP: u32 = 6;

pub const RPC_CMD_LOAD_TA: u32 = 0;
pub const RPC_CMD_FS: u32 = 2;
pub const RPC_CMD_GET_TIME: u32 = 3;
pub const RPC_CMD_NOTIFICATION: u32 = 4;
pub const RPC_CMD_SUSPEND: u32 = 5;
pub const RPC_CMD_SHM_ALLOC: u32 = 6;
pub const RPC_CMD_SHM_FREE: u32 = 7;

pub const RPC_FS_OPEN: u32 = 0;
pub const RPC_FS_CREATE: u32 = 1;
pub const RPC_FS_CLOSE: u32 = 2;
pub const RPC_FS_READ: u32 = 3;
pub const RPC_FS_WRITE: u32 = 4;
pub const RPC_FS_TRUNCATE: u32 = 5;
pub const RPC_FS_REMOVE: u32 = 6;
pub const RPC_FS_RENAME: u32 = 7;
pub const RPC_FS_OPENDIR: u32 = 8;
pub const RPC_FS_CLOSEDIR: u32 = 9;
pub const RPC_FS_READDIR: u32 = 10;

pub const RPC_SHM_TYPE_APPL: u32 = 0;
pub const RPC_SHM_TYPE_KERNEL: u32 = 1;
pub const RPC_SHM_TYPE_GLOBAL: u32 = 2;

/// SMCCC: FAST | OWNER_TRUSTED_OS_API(63) | func
pub const SMC_CALLS_UID: u32 = 0xBF00_FF01;
pub const SMC_CALLS_REVISION: u32 = 0xBF00_FF03;
/// FAST | OWNER_TRUSTED_OS(50) | func
pub const SMC_GET_OS_UUID: u32 = 0xB200_0000;
pub const SMC_GET_OS_REVISION: u32 = 0xB200_0001;
pub const SMC_GET_SHM_CONFIG: u32 = 0xB200_0007;
pub const SMC_EXCHANGE_CAPABILITIES: u32 = 0xB200_0009;
pub const SMC_GET_THREAD_COUNT: u32 = 0xB200_000F;
/// STD | OWNER_TRUSTED_OS(50) | func
pub const SMC_CALL_WITH_ARG: u32 = 0x3200_0004;
pub const SMC_RETURN_FROM_RPC: u32 = 0x3200_0003;

pub const SMC_RETURN_OK: u32 = 0;
pub const SMC_RETURN_ETHREAD_LIMIT: u32 = 1;
pub const SMC_RETURN_EBUSY: u32 = 2;
pub const SMC_RETURN_EBADADDR: u32 = 4;
pub const SMC_RETURN_EBADCMD: u32 = 5;
pub const SMC_RETURN_ENOMEM: u32 = 6;
pub const SMC_RETURN_ENOTAVAIL: u32 = 7;
pub const SMC_RETURN_UNKNOWN_FUNCTION: u32 = 0xFFFF_FFFF;

pub const SEC_CAP_UNREGISTERED_SHM: u32 = 1 << 1;
pub const SEC_CAP_DYNAMIC_SHM: u32 = 1 << 2;
pub const SEC_CAP_MEMREF_NULL: u32 = 1 << 4;
pub const V0_SEC_CAPS: u32 =
    SEC_CAP_UNREGISTERED_SHM | SEC_CAP_DYNAMIC_SHM | SEC_CAP_MEMREF_NULL;

pub const ORIGIN_API: u32 = 1;
pub const ORIGIN_COMMS: u32 = 2;
pub const ORIGIN_TEE: u32 = 3;
pub const ORIGIN_TRUSTED_APP: u32 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtoError {
    Truncated,
    BadKind,
    BadAlign,
    BadCmd,
    BounceOob,
}

/// 8 SMCCC-shaped registers. vsock PDU arg is this, 64 bytes LE. Not the MSG blob.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct CallFrame {
    pub r: [u64; 8],
}

impl CallFrame {
    pub fn yielding_enter(cookie: u64) -> Self {
        let mut f = Self::default();
        f.r[0] = SMC_CALL_WITH_ARG as u64;
        f.set_cookie(cookie);
        f
    }

    pub fn return_from_rpc(cookie: u64) -> Self {
        let mut f = Self::default();
        f.r[0] = SMC_RETURN_FROM_RPC as u64;
        f.set_cookie(cookie);
        f
    }

    /// CALL_WITH_ARG packing: a1 = high 32, a2 = low 32.
    pub fn cookie(&self) -> u64 {
        (self.r[1] << 32) | (self.r[2] & 0xffff_ffff)
    }

    pub fn set_cookie(&mut self, cookie: u64) {
        self.r[1] = cookie >> 32;
        self.r[2] = cookie & 0xffff_ffff;
    }

    pub fn encode(self) -> [u8; CALL_FRAME_LEN] {
        let mut b = [0u8; CALL_FRAME_LEN];
        for (i, w) in self.r.iter().enumerate() {
            let o = i * 8;
            b[o..o + 8].copy_from_slice(&w.to_le_bytes());
        }
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self, ProtoError> {
        if b.len() < CALL_FRAME_LEN {
            return Err(ProtoError::Truncated);
        }
        let mut r = [0u64; 8];
        for i in 0..8 {
            let o = i * 8;
            r[i] = u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        }
        Ok(Self { r })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PduHeader {
    pub kind: u32,
    pub seq: u32,
    pub arg_len: u32,
    pub bounce_len: u32,
}

impl PduHeader {
    pub fn yielding(kind: u32, seq: u32, bounce_len: u32) -> Self {
        Self {
            kind,
            seq,
            arg_len: CALL_FRAME_LEN as u32,
            bounce_len,
        }
    }

    pub fn encode(self) -> [u8; PDU_HDR_LEN] {
        let mut b = [0u8; PDU_HDR_LEN];
        b[0..4].copy_from_slice(&self.kind.to_le_bytes());
        b[4..8].copy_from_slice(&self.seq.to_le_bytes());
        b[8..12].copy_from_slice(&self.arg_len.to_le_bytes());
        b[12..16].copy_from_slice(&self.bounce_len.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self, ProtoError> {
        if b.len() < PDU_HDR_LEN {
            return Err(ProtoError::Truncated);
        }
        let kind = u32::from_le_bytes(b[0..4].try_into().unwrap());
        match kind {
            KIND_ENTER | KIND_RPC | KIND_COMPLETE | KIND_RPC_REPLY => {}
            _ => return Err(ProtoError::BadKind),
        }
        let arg_len = u32::from_le_bytes(b[8..12].try_into().unwrap());
        if arg_len != CALL_FRAME_LEN as u32 {
            return Err(ProtoError::Truncated);
        }
        Ok(Self {
            kind,
            seq: u32::from_le_bytes(b[4..8].try_into().unwrap()),
            arg_len,
            bounce_len: u32::from_le_bytes(b[12..16].try_into().unwrap()),
        })
    }
}

/// Fixed header of struct optee_msg_arg (params follow). Independently laid out.
pub const MSG_ARG_HDR_SIZE: usize = 32;
pub const MSG_PARAM_SIZE: usize = 32;

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct MsgArgHdr {
    pub cmd: u32,
    pub func: u32,
    pub session: u32,
    pub cancel_id: u32,
    pub pad: u32,
    pub ret: u32,
    pub ret_origin: u32,
    pub num_params: u32,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct MsgParam {
    pub attr: u64,
    pub a: u64,
    pub b: u64,
    pub c: u64,
}

impl MsgArgHdr {
    pub fn encode(self, out: &mut [u8]) -> Result<(), ProtoError> {
        if out.len() < MSG_ARG_HDR_SIZE {
            return Err(ProtoError::Truncated);
        }
        write_u32_le(out, 0, self.cmd);
        write_u32_le(out, 4, self.func);
        write_u32_le(out, 8, self.session);
        write_u32_le(out, 12, self.cancel_id);
        write_u32_le(out, 16, self.pad);
        write_u32_le(out, 20, self.ret);
        write_u32_le(out, 24, self.ret_origin);
        write_u32_le(out, 28, self.num_params);
        Ok(())
    }

    pub fn decode(b: &[u8]) -> Result<Self, ProtoError> {
        if b.len() < MSG_ARG_HDR_SIZE {
            return Err(ProtoError::Truncated);
        }
        Ok(Self {
            cmd: read_u32_le(b, 0),
            func: read_u32_le(b, 4),
            session: read_u32_le(b, 8),
            cancel_id: read_u32_le(b, 12),
            pad: read_u32_le(b, 16),
            ret: read_u32_le(b, 20),
            ret_origin: read_u32_le(b, 24),
            num_params: read_u32_le(b, 28),
        })
    }

    pub fn byte_size(&self) -> usize {
        MSG_ARG_HDR_SIZE + MSG_PARAM_SIZE * self.num_params as usize
    }
}

impl MsgParam {
    pub fn encode(self, out: &mut [u8]) -> Result<(), ProtoError> {
        if out.len() < MSG_PARAM_SIZE {
            return Err(ProtoError::Truncated);
        }
        write_u64_le(out, 0, self.attr);
        write_u64_le(out, 8, self.a);
        write_u64_le(out, 16, self.b);
        write_u64_le(out, 24, self.c);
        Ok(())
    }

    pub fn decode(b: &[u8]) -> Result<Self, ProtoError> {
        if b.len() < MSG_PARAM_SIZE {
            return Err(ProtoError::Truncated);
        }
        Ok(Self {
            attr: read_u64_le(b, 0),
            a: read_u64_le(b, 8),
            b: read_u64_le(b, 16),
            c: read_u64_le(b, 24),
        })
    }

    pub fn value(attr: u64, a: u64, b: u64, c: u64) -> Self {
        Self { attr, a, b, c }
    }

    pub fn tmem(attr: u64, buf_ptr: u64, size: u64, shm_ref: u64) -> Self {
        Self {
            attr,
            a: buf_ptr,
            b: size,
            c: shm_ref,
        }
    }

    pub fn rmem(attr: u64, offs: u64, size: u64, shm_ref: u64) -> Self {
        Self {
            attr,
            a: offs,
            b: size,
            c: shm_ref,
        }
    }
}

/// Place MSG + params at `cookie` in `pool`. cookie must be 8-aligned.
pub fn write_msg(
    pool: &mut [u8],
    cookie: u64,
    hdr: MsgArgHdr,
    params: &[MsgParam],
) -> Result<usize, ProtoError> {
    if cookie % MSG_ARG_ALIGN as u64 != 0 {
        return Err(ProtoError::BadAlign);
    }
    if params.len() != hdr.num_params as usize {
        return Err(ProtoError::BadCmd);
    }
    let off = cookie as usize;
    let n = hdr.byte_size();
    if off.checked_add(n).map(|e| e > pool.len()).unwrap_or(true) {
        return Err(ProtoError::BounceOob);
    }
    hdr.encode(&mut pool[off..off + MSG_ARG_HDR_SIZE])?;
    for (i, p) in params.iter().enumerate() {
        let s = off + MSG_ARG_HDR_SIZE + i * MSG_PARAM_SIZE;
        p.encode(&mut pool[s..s + MSG_PARAM_SIZE])?;
    }
    Ok(n)
}

/// Small param array without alloc. GP Client is 4 user + 2 meta on open.
pub type ParamBuf = [MsgParam; 6];

pub fn decode_msg(pool: &[u8], cookie: u64) -> Result<(MsgArgHdr, ParamBuf, usize), ProtoError> {
    if cookie % MSG_ARG_ALIGN as u64 != 0 {
        return Err(ProtoError::BadAlign);
    }
    let off = cookie as usize;
    if off + MSG_ARG_HDR_SIZE > pool.len() {
        return Err(ProtoError::BounceOob);
    }
    let hdr = MsgArgHdr::decode(&pool[off..])?;
    if hdr.num_params as usize > 6 {
        return Err(ProtoError::BadCmd);
    }
    let n = hdr.byte_size();
    if off + n > pool.len() {
        return Err(ProtoError::BounceOob);
    }
    let mut params = [MsgParam::default(); 6];
    for i in 0..hdr.num_params as usize {
        let s = off + MSG_ARG_HDR_SIZE + i * MSG_PARAM_SIZE;
        params[i] = MsgParam::decode(&pool[s..])?;
    }
    Ok((hdr, params, n))
}

/// Fast SMCCC answered in rustee-virt.ko / gp-client. Never sent on vsock.
/// Returns (a0, a1, a2, a3).
pub fn answer_fast_smccc(a0: u32, a1: u32) -> Option<[u32; 4]> {
    let _ = a1;
    match a0 {
        SMC_CALLS_UID => Some([
            CALLS_UID_WORDS[0],
            CALLS_UID_WORDS[1],
            CALLS_UID_WORDS[2],
            CALLS_UID_WORDS[3],
        ]),
        SMC_CALLS_REVISION => Some([2, 0, 0, 0]),
        SMC_GET_OS_UUID => Some([
            OS_UUID_WORDS[0],
            OS_UUID_WORDS[1],
            OS_UUID_WORDS[2],
            OS_UUID_WORDS[3],
        ]),
        SMC_GET_OS_REVISION => Some([OS_REVISION_MAJOR, OS_REVISION_MINOR, 0, 0]),
        SMC_EXCHANGE_CAPABILITIES => Some([SMC_RETURN_OK, V0_SEC_CAPS, 0, 0]),
        SMC_GET_SHM_CONFIG => Some([SMC_RETURN_ENOTAVAIL, 0, 0, 0]),
        SMC_GET_THREAD_COUNT => Some([SMC_RETURN_OK, 1, 0, 0]),
        _ => None,
    }
}

fn write_u32_le(out: &mut [u8], off: usize, v: u32) {
    out[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn write_u64_le(out: &mut [u8], off: usize, v: u64) {
    out[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
fn read_u32_le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn read_u64_le(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callframe_is_64() {
        assert_eq!(core::mem::size_of::<CallFrame>(), 64);
        assert_eq!(PDU_HDR_LEN, 16);
    }

    #[test]
    fn cookie_smccc_high_low() {
        let mut f = CallFrame::default();
        f.set_cookie(0x0000_0001_2345_6789);
        assert_eq!(f.r[1], 0x0000_0001);
        assert_eq!(f.r[2], 0x2345_6789);
        assert_eq!(f.cookie(), 0x0000_0001_2345_6789);
        let enc = f.encode();
        let dec = CallFrame::decode(&enc).unwrap();
        assert_eq!(dec.cookie(), f.cookie());
    }

    #[test]
    fn pdu_arg_len_is_64() {
        let h = PduHeader::yielding(KIND_ENTER, 7, 128);
        assert_eq!(h.arg_len, 64);
        let b = h.encode();
        let d = PduHeader::decode(&b).unwrap();
        assert_eq!(d, h);
    }

    #[test]
    fn msg_lives_in_bounce_not_pdu_arg() {
        let mut pool = [0u8; 4096];
        let cookie = 64u64;
        let hdr = MsgArgHdr {
            cmd: MSG_CMD_OPEN_SESSION,
            num_params: 2,
            ..MsgArgHdr::default()
        };
        let params = [
            MsgParam::value(ATTR_TYPE_VALUE_INPUT | ATTR_META, 0x11, 0x22, 0),
            MsgParam::value(ATTR_TYPE_VALUE_INPUT | ATTR_META, 0, 0, MSG_LOGIN_PUBLIC as u64),
        ];
        let n = write_msg(&mut pool, cookie, hdr, &params).unwrap();
        let (h2, p2, n2) = decode_msg(&pool, cookie).unwrap();
        assert_eq!(n, n2);
        assert_eq!(h2.cmd, MSG_CMD_OPEN_SESSION);
        assert_eq!(p2[0].a, 0x11);
        let f = CallFrame::yielding_enter(cookie);
        assert_eq!(f.r[0], SMC_CALL_WITH_ARG as u64);
        assert_eq!(f.cookie(), cookie);
        assert_eq!(CALL_FRAME_LEN, 64);
    }

    #[test]
    fn fast_smccc_local() {
        let uid = answer_fast_smccc(SMC_CALLS_UID, 0).unwrap();
        assert_eq!(uid, CALLS_UID_WORDS);
        let os = answer_fast_smccc(SMC_GET_OS_UUID, 0).unwrap();
        assert_eq!(os, OS_UUID_WORDS);
        assert_ne!(OS_UUID_WORDS[0], 0x4861_78e0);
        let caps = answer_fast_smccc(SMC_EXCHANGE_CAPABILITIES, 0).unwrap();
        assert_eq!(caps[1], V0_SEC_CAPS);
        let shm = answer_fast_smccc(SMC_GET_SHM_CONFIG, 0).unwrap();
        assert_eq!(shm[0], SMC_RETURN_ENOTAVAIL);
        let thr = answer_fast_smccc(SMC_GET_THREAD_COUNT, 0).unwrap();
        assert_eq!(thr[1], 1);
        assert!(answer_fast_smccc(SMC_CALL_WITH_ARG, 0).is_none());
    }

    #[test]
    fn cmds_are_v0_subset() {
        assert_eq!(MSG_CMD_OPEN_SESSION, 0);
        assert_eq!(MSG_CMD_UNREGISTER_SHM, 5);
        assert_eq!(RPC_CMD_LOAD_TA, 0);
        assert_eq!(RPC_CMD_GET_TIME, 3);
        assert_eq!(RPC_CMD_FS, 2);
    }
}
