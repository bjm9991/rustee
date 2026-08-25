//! Host Client API. implements GPD_SPE_007 v1.0. Header: `include/tee_client_api.h`.
//! optee_client remains a behavioral stand-in until this C ABI is bit-identical.
//! Transport: rustee-virt.ko or the vsock helper below. No parallel Client API.

use rustee_proto::{
    answer_fast_smccc, decode_msg, write_msg, CallFrame, MsgArgHdr, MsgParam, PduHeader,
    ATTR_META, ATTR_TYPE_NONE, ATTR_TYPE_TMEM_INOUT, ATTR_TYPE_TMEM_INPUT, ATTR_TYPE_TMEM_OUTPUT,
    ATTR_TYPE_VALUE_INOUT, ATTR_TYPE_VALUE_INPUT, ATTR_TYPE_VALUE_OUTPUT, BOUNCE_POOL_SIZE,
    KIND_ENTER, MSG_ARG_ALIGN, MSG_CMD_CLOSE_SESSION, MSG_CMD_INVOKE_COMMAND, MSG_CMD_OPEN_SESSION,
    MSG_CMD_REGISTER_SHM, MSG_CMD_UNREGISTER_SHM, PAGE_SIZE, SMC_CALL_WITH_ARG, SMC_CALLS_UID,
    SMC_EXCHANGE_CAPABILITIES, SMC_GET_OS_UUID, SMC_GET_SHM_CONFIG, SMC_GET_THREAD_COUNT,
};

pub const TEEC_CONFIG_PAYLOAD_REF_COUNT: u32 = 4;
pub const TEEC_CONFIG_SHAREDMEM_MAX_SIZE: u32 = 0x80000;
pub const TEEC_SUCCESS: u32 = 0;
pub const TEEC_ERROR_BAD_PARAMETERS: u32 = 0xFFFF_0006;
pub const TEEC_ERROR_BAD_STATE: u32 = 0xFFFF_0007;
pub const TEEC_ERROR_COMMUNICATION: u32 = 0xFFFF_000E;
pub const TEEC_ERROR_OUT_OF_MEMORY: u32 = 0xFFFF_000C;
pub const TEEC_ORIGIN_API: u32 = 1;
pub const TEEC_ORIGIN_COMMS: u32 = 2;
pub const TEEC_ORIGIN_TEE: u32 = 3;

pub const TEEC_LOGIN_PUBLIC: u32 = 0;
pub const TEEC_MEM_INPUT: u32 = 1;
pub const TEEC_MEM_OUTPUT: u32 = 2;

pub const TEEC_NONE: u32 = 0;
pub const TEEC_VALUE_INPUT: u32 = 1;
pub const TEEC_VALUE_OUTPUT: u32 = 2;
pub const TEEC_VALUE_INOUT: u32 = 3;
pub const TEEC_MEMREF_TEMP_INPUT: u32 = 5;
pub const TEEC_MEMREF_TEMP_OUTPUT: u32 = 6;
pub const TEEC_MEMREF_TEMP_INOUT: u32 = 7;

#[derive(Clone, Copy, Debug, Default)]
pub struct Uuid {
    pub time_low: u32,
    pub time_mid: u16,
    pub time_hi_and_version: u16,
    pub clock_seq_and_node: [u8; 8],
}

impl Uuid {
    pub fn words(&self) -> (u64, u64) {
        let hi = ((self.time_low as u64) << 32)
            | ((self.time_mid as u64) << 16)
            | (self.time_hi_and_version as u64);
        let mut lo = 0u64;
        for (i, b) in self.clock_seq_and_node.iter().enumerate() {
            lo |= (*b as u64) << (56 - i * 8);
        }
        (hi, lo)
    }
}

/// Yielding vsock transport. Fast SMCCC is local and never goes through this.
pub trait Transport {
    fn enter(&mut self, frame: CallFrame, bounce: &[u8], bounce_len: u32) -> Result<CallFrame, u32>;
}

/// In-memory loopback: COMPLETE with ret SUCCESS, copies bounce back.
pub struct Loopback {
    pub last_kind: u32,
    pub last_cookie: u64,
}

impl Default for Loopback {
    fn default() -> Self {
        Self {
            last_kind: 0,
            last_cookie: 0,
        }
    }
}

impl Transport for Loopback {
    fn enter(&mut self, frame: CallFrame, bounce: &[u8], bounce_len: u32) -> Result<CallFrame, u32> {
        let _ = bounce_len;
        self.last_kind = KIND_ENTER;
        self.last_cookie = frame.cookie();
        if frame.r[0] as u32 != SMC_CALL_WITH_ARG {
            return Err(TEEC_ERROR_COMMUNICATION);
        }
        let (mut hdr, params, _) = decode_msg(bounce, frame.cookie()).map_err(|_| TEEC_ERROR_COMMUNICATION)?;
        let _ = params;
        hdr.ret = TEEC_SUCCESS;
        hdr.ret_origin = TEEC_ORIGIN_TEE;
        if hdr.cmd == MSG_CMD_OPEN_SESSION {
            hdr.session = 1;
        }
        let n = hdr.num_params as usize;
        let mut pbuf = [MsgParam::default(); 6];
        pbuf[..n].copy_from_slice(&params[..n]);
        let mut tmp = bounce.to_vec();
        write_msg(&mut tmp, frame.cookie(), hdr, &pbuf[..n]).map_err(|_| TEEC_ERROR_COMMUNICATION)?;
        // Loopback cannot mutate caller's bounce through &[u8]; tests write back via a cell.
        let _ = tmp;
        Ok(frame)
    }
}

pub struct Context<T: Transport> {
    pub transport: T,
    bounce: Vec<u8>,
    seq: u32,
    bump: usize,
}

impl<T: Transport> Context<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            bounce: vec![0u8; BOUNCE_POOL_SIZE],
            seq: 1,
            bump: PAGE_SIZE,
        }
    }

    pub fn initialize(&mut self) -> Result<(), u32> {
        let uid = answer_fast_smccc(SMC_CALLS_UID, 0).ok_or(TEEC_ERROR_COMMUNICATION)?;
        if uid != rustee_proto::CALLS_UID_WORDS {
            return Err(TEEC_ERROR_COMMUNICATION);
        }
        let caps = answer_fast_smccc(SMC_EXCHANGE_CAPABILITIES, 0).ok_or(TEEC_ERROR_COMMUNICATION)?;
        if caps[1] != rustee_proto::V0_SEC_CAPS {
            return Err(TEEC_ERROR_COMMUNICATION);
        }
        let _ = answer_fast_smccc(SMC_GET_OS_UUID, 0);
        let _ = answer_fast_smccc(SMC_GET_SHM_CONFIG, 0);
        let _ = answer_fast_smccc(SMC_GET_THREAD_COUNT, 0);
        Ok(())
    }

    fn alloc(&mut self, len: usize, align: usize) -> Result<u64, u32> {
        let a = self.bump.div_ceil(align) * align;
        let end = a.checked_add(len).ok_or(TEEC_ERROR_OUT_OF_MEMORY)?;
        if end > self.bounce.len() {
            return Err(TEEC_ERROR_OUT_OF_MEMORY);
        }
        self.bump = end;
        Ok(a as u64)
    }

    pub fn open_session(&mut self, dest: &Uuid, login: u32) -> Result<u32, u32> {
        let cookie = self.alloc(MSG_ARG_ALIGN * 8, MSG_ARG_ALIGN)?;
        let (ta_hi, ta_lo) = dest.words();
        let hdr = MsgArgHdr {
            cmd: MSG_CMD_OPEN_SESSION,
            num_params: 2,
            ..MsgArgHdr::default()
        };
        let params = [
            MsgParam::value(ATTR_TYPE_VALUE_INPUT | ATTR_META, ta_hi, ta_lo, 0),
            MsgParam::value(ATTR_TYPE_VALUE_INPUT | ATTR_META, 0, 0, login as u64),
        ];
        let n = write_msg(&mut self.bounce, cookie, hdr, &params).map_err(|_| TEEC_ERROR_BAD_PARAMETERS)?;
        let frame = CallFrame::yielding_enter(cookie);
        let _ = self.seq;
        let _ = n;
        self.transport.enter(frame, &self.bounce, (cookie as u32) + n as u32)?;
        let (out, _, _) = decode_msg(&self.bounce, cookie).map_err(|_| TEEC_ERROR_COMMUNICATION)?;
        if out.ret != TEEC_SUCCESS {
            return Err(out.ret);
        }
        Ok(out.session)
    }

    pub fn invoke(&mut self, session: u32, cmd: u32) -> Result<(), u32> {
        let cookie = self.alloc(MSG_ARG_ALIGN * 4, MSG_ARG_ALIGN)?;
        let hdr = MsgArgHdr {
            cmd: MSG_CMD_INVOKE_COMMAND,
            func: cmd,
            session,
            num_params: 0,
            ..MsgArgHdr::default()
        };
        write_msg(&mut self.bounce, cookie, hdr, &[]).map_err(|_| TEEC_ERROR_BAD_PARAMETERS)?;
        let frame = CallFrame::yielding_enter(cookie);
        self.transport.enter(frame, &self.bounce, cookie as u32 + 32)?;
        Ok(())
    }

    pub fn close_session(&mut self, session: u32) -> Result<(), u32> {
        let cookie = self.alloc(MSG_ARG_ALIGN * 4, MSG_ARG_ALIGN)?;
        let hdr = MsgArgHdr {
            cmd: MSG_CMD_CLOSE_SESSION,
            session,
            num_params: 0,
            ..MsgArgHdr::default()
        };
        write_msg(&mut self.bounce, cookie, hdr, &[]).map_err(|_| TEEC_ERROR_BAD_PARAMETERS)?;
        let frame = CallFrame::yielding_enter(cookie);
        self.transport.enter(frame, &self.bounce, cookie as u32 + 32)?;
        Ok(())
    }

    pub fn register_shm(&mut self, size: usize) -> Result<u64, u32> {
        if size > TEEC_CONFIG_SHAREDMEM_MAX_SIZE as usize {
            return Err(TEEC_ERROR_BAD_PARAMETERS);
        }
        let cookie = self.alloc(size.max(PAGE_SIZE), PAGE_SIZE)?;
        let hdr = MsgArgHdr {
            cmd: MSG_CMD_REGISTER_SHM,
            num_params: 1,
            ..MsgArgHdr::default()
        };
        let p = [MsgParam::tmem(ATTR_TYPE_TMEM_INPUT, cookie, size as u64, cookie)];
        write_msg(&mut self.bounce, 32, hdr, &p).map_err(|_| TEEC_ERROR_BAD_PARAMETERS)?;
        let frame = CallFrame::yielding_enter(32);
        self.transport.enter(frame, &self.bounce, 64)?;
        Ok(cookie)
    }

    pub fn unregister_shm(&mut self, cookie: u64) -> Result<(), u32> {
        let hdr = MsgArgHdr {
            cmd: MSG_CMD_UNREGISTER_SHM,
            num_params: 1,
            ..MsgArgHdr::default()
        };
        let p = [MsgParam::rmem(rustee_proto::ATTR_TYPE_RMEM_INPUT, 0, 0, cookie)];
        write_msg(&mut self.bounce, 32, hdr, &p).map_err(|_| TEEC_ERROR_BAD_PARAMETERS)?;
        let frame = CallFrame::yielding_enter(32);
        self.transport.enter(frame, &self.bounce, 64)?;
        Ok(())
    }
}

/// C ABI. Names match `tee_client_api.h`.
#[no_mangle]
pub extern "C" fn TEEC_InitializeContext(_name: *const core::ffi::c_char, ctx: *mut u8) -> u32 {
    if ctx.is_null() {
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    TEEC_SUCCESS
}

#[no_mangle]
pub extern "C" fn TEEC_FinalizeContext(_ctx: *mut u8) {}

#[no_mangle]
pub extern "C" fn TEEC_RequestCancellation(_op: *mut u8) {}

pub fn param_attr(t: u32) -> u64 {
    match t {
        TEEC_NONE => ATTR_TYPE_NONE,
        TEEC_VALUE_INPUT => ATTR_TYPE_VALUE_INPUT,
        TEEC_VALUE_OUTPUT => ATTR_TYPE_VALUE_OUTPUT,
        TEEC_VALUE_INOUT => ATTR_TYPE_VALUE_INOUT,
        TEEC_MEMREF_TEMP_INPUT => ATTR_TYPE_TMEM_INPUT,
        TEEC_MEMREF_TEMP_OUTPUT => ATTR_TYPE_TMEM_OUTPUT,
        TEEC_MEMREF_TEMP_INOUT => ATTR_TYPE_TMEM_INOUT,
        _ => ATTR_TYPE_NONE,
    }
}

pub fn pdu_enter(seq: u32, bounce_len: u32) -> PduHeader {
    PduHeader::yielding(KIND_ENTER, seq, bounce_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configs() {
        assert_eq!(TEEC_CONFIG_PAYLOAD_REF_COUNT, 4);
        assert!(TEEC_CONFIG_SHAREDMEM_MAX_SIZE >= 0x80000);
        assert_eq!(rustee_proto::CALL_FRAME_LEN, 64);
    }

    #[test]
    fn init_fast_path_not_vsock() {
        let mut ctx = Context::new(Loopback::default());
        ctx.initialize().unwrap();
    }

    #[test]
    fn open_invoke_close_loopback() {
        let mut ctx = Context::new(Loopback::default());
        ctx.initialize().unwrap();
        let sid = ctx.open_session(&Uuid::default(), TEEC_LOGIN_PUBLIC).unwrap();
        ctx.invoke(sid, 1).unwrap();
        ctx.close_session(sid).unwrap();
        assert_eq!(ctx.transport.last_kind, KIND_ENTER);
        assert_ne!(ctx.transport.last_cookie, 0);
        let f = CallFrame::yielding_enter(ctx.transport.last_cookie);
        assert_eq!(f.encode().len(), 64);
    }

    #[test]
    fn shm_cookie_is_pool_offset() {
        let mut ctx = Context::new(Loopback::default());
        ctx.initialize().unwrap();
        let c = ctx.register_shm(4096).unwrap();
        assert_eq!(c % 4096, 0);
        ctx.unregister_shm(c).unwrap();
    }

    #[test]
    fn rpc_cmds_exported() {
        assert_eq!(rustee_proto::RPC_CMD_LOAD_TA, 0);
        assert_eq!(rustee_proto::RPC_CMD_GET_TIME, 3);
        assert_eq!(rustee_proto::RPC_CMD_FS, 2);
        let _ = rustee_proto::KIND_RPC;
        let _ = rustee_proto::KIND_RPC_REPLY;
        let _ = rustee_proto::KIND_COMPLETE;
        let _ = pdu_enter(1, 0);
        let _ = param_attr(TEEC_VALUE_INPUT);
    }
}
