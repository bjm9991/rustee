//! MSG in bounce → rustee-os KernelCmd. Kernel never sees MSG.
use rustee_os::{
    Dir, KernelCmd, Login, MemrefSrc, Param, SessionId, Uuid, PARAM_COUNT, TEE_TIMEOUT_INFINITE,
};
use rustee_proto::{
    decode_msg, MsgArgHdr, MsgParam, ATTR_META, ATTR_TYPE_MASK, ATTR_TYPE_NONE,
    ATTR_TYPE_TMEM_INOUT, ATTR_TYPE_TMEM_INPUT, ATTR_TYPE_TMEM_OUTPUT, ATTR_TYPE_VALUE_INOUT,
    ATTR_TYPE_VALUE_INPUT, ATTR_TYPE_VALUE_OUTPUT, MSG_CMD_CANCEL, MSG_CMD_CLOSE_SESSION,
    MSG_CMD_INVOKE_COMMAND, MSG_CMD_OPEN_SESSION, MSG_LOGIN_PUBLIC,
};

fn ty(p: MsgParam) -> u64 {
    p.attr & ATTR_TYPE_MASK
}

fn dir_of(t: u64) -> Dir {
    match t {
        ATTR_TYPE_TMEM_INPUT | ATTR_TYPE_VALUE_INPUT => Dir::In,
        ATTR_TYPE_TMEM_OUTPUT | ATTR_TYPE_VALUE_OUTPUT => Dir::Out,
        _ => Dir::InOut,
    }
}

fn param(p: MsgParam) -> Param {
    match ty(p) {
        ATTR_TYPE_NONE => Param::None,
        ATTR_TYPE_VALUE_INPUT | ATTR_TYPE_VALUE_OUTPUT | ATTR_TYPE_VALUE_INOUT => Param::Value {
            a: p.a as u32,
            b: p.b as u32,
            dir: dir_of(ty(p)),
        },
        ATTR_TYPE_TMEM_INPUT | ATTR_TYPE_TMEM_OUTPUT | ATTR_TYPE_TMEM_INOUT => Param::Memref {
            src: MemrefSrc::Ree {
                cookie: p.a,
                offs: 0,
            },
            size: p.b as usize,
            dir: dir_of(ty(p)),
        },
        _ => Param::None,
    }
}

/// Inverse of gp-client `Uuid::words`: hi = (time_low<<32)|(time_mid<<16)|time_hi,
/// lo = clock_seq_and_node packed big-endian. Bytes match `Uuid::from_bytes`.
fn uuid_from_words(hi: u64, lo: u64) -> Uuid {
    let time_low = (hi >> 32) as u32;
    let time_mid = (hi >> 16) as u16;
    let time_hi = hi as u16;
    let mut b = [0u8; 16];
    b[0..4].copy_from_slice(&time_low.to_be_bytes());
    b[4..6].copy_from_slice(&time_mid.to_be_bytes());
    b[6..8].copy_from_slice(&time_hi.to_be_bytes());
    b[8..16].copy_from_slice(&lo.to_be_bytes());
    Uuid(b)
}

/// Decode MSG in place from the live bounce slice. `pool` is the bounce, not a clone.
pub fn decode_cmd(pool: &[u8], cookie: u64) -> Result<KernelCmd, ()> {
    let (hdr, params, _) = decode_msg(pool, cookie).map_err(|_| ())?;
    match hdr.cmd {
        MSG_CMD_OPEN_SESSION => {
            let mut uuid = Uuid([0; 16]);
            let mut login = Login::Public;
            let mut user = [Param::None; PARAM_COUNT];
            let mut ui = 0usize;
            for i in 0..hdr.num_params as usize {
                let p = params[i];
                if p.attr & ATTR_META != 0 {
                    if ty(p) == ATTR_TYPE_VALUE_INPUT && i == 0 {
                        uuid = uuid_from_words(p.a, p.b);
                    } else if (p.c as u32) == MSG_LOGIN_PUBLIC {
                        login = Login::Public;
                    }
                } else if ui < PARAM_COUNT {
                    user[ui] = param(p);
                    ui += 1;
                }
            }
            Ok(KernelCmd::OpenSession {
                uuid,
                login,
                params: user,
                cancel_id: hdr.cancel_id,
                timeout_ms: TEE_TIMEOUT_INFINITE,
            })
        }
        MSG_CMD_INVOKE_COMMAND => {
            let mut user = [Param::None; PARAM_COUNT];
            let mut ui = 0usize;
            for i in 0..hdr.num_params as usize {
                if params[i].attr & ATTR_META != 0 {
                    continue;
                }
                if ui < PARAM_COUNT {
                    user[ui] = param(params[i]);
                    ui += 1;
                }
            }
            Ok(KernelCmd::Invoke {
                session: SessionId(hdr.session),
                cmd_id: hdr.func,
                params: user,
                cancel_id: hdr.cancel_id,
                timeout_ms: TEE_TIMEOUT_INFINITE,
            })
        }
        MSG_CMD_CLOSE_SESSION => Ok(KernelCmd::CloseSession {
            session: SessionId(hdr.session),
        }),
        MSG_CMD_CANCEL => Ok(KernelCmd::Cancel {
            cancel_id: hdr.cancel_id,
        }),
        _ => Err(()),
    }
}

pub fn write_done(pool: &mut [u8], cookie: u64, ret: u32, origin: u32, session: u32) {
    if let Ok((mut hdr, params, _)) = decode_msg(pool, cookie) {
        hdr.ret = ret;
        hdr.ret_origin = origin;
        hdr.session = session;
        let n = hdr.num_params as usize;
        let _ = rustee_proto::write_msg(pool, cookie, hdr, &params[..n]);
    }
    let _ = MsgArgHdr::default();
}
