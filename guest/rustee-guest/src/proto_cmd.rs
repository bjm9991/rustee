//! MSG in bounce → rustee-os KernelCmd. Kernel never sees MSG.
use rustee_os::{
    Dir, KernelCmd, Login, MemrefSrc, Param, SessionId, Uuid, PARAM_COUNT,
    TEE_ERROR_BAD_PARAMETERS, TEE_ERROR_ITEM_NOT_FOUND, TEE_TIMEOUT_INFINITE,
};
use rustee_proto::{
    decode_msg, write_msg, MsgArgHdr, MsgParam, ATTR_META, ATTR_TYPE_MASK, ATTR_TYPE_NONE,
    ATTR_TYPE_TMEM_INOUT, ATTR_TYPE_TMEM_INPUT, ATTR_TYPE_TMEM_OUTPUT, ATTR_TYPE_VALUE_INOUT,
    ATTR_TYPE_VALUE_INPUT, ATTR_TYPE_VALUE_OUTPUT, MSG_ARG_HDR_SIZE, MSG_CMD_CANCEL,
    MSG_CMD_CLOSE_SESSION, MSG_CMD_INVOKE_COMMAND, MSG_CMD_OPEN_SESSION, MSG_LOGIN_PUBLIC,
    MSG_PARAM_SIZE, RPC_CMD_LOAD_TA,
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

/// Free bounce offset for RPC MSG. CA cookies grow from 0; 8 MiB cannot collide in v0.
pub const RPC_COOKIE: u64 = 0x80_0000;
/// LOAD_TA tmem capacity. Client #33 copies the ELF here and may expand RPC_REPLY bounce_len.
pub const LOAD_TA_CAP: u64 = 2 * 1024 * 1024;

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

/// gp-client `Uuid::words`. Filename `{hi:016x}{lo:016x}` matches hello-rs
/// `8d825f6a1c4b4c9f9e3a2b7c6d5e4f30`.
pub fn uuid_to_words(u: Uuid) -> (u64, u64) {
    let time_low = u32::from_be_bytes([u.0[0], u.0[1], u.0[2], u.0[3]]);
    let time_mid = u16::from_be_bytes([u.0[4], u.0[5]]);
    let time_hi = u16::from_be_bytes([u.0[6], u.0[7]]);
    let hi = ((time_low as u64) << 32) | ((time_mid as u64) << 16) | (time_hi as u64);
    let lo = u64::from_be_bytes([
        u.0[8], u.0[9], u.0[10], u.0[11], u.0[12], u.0[13], u.0[14], u.0[15],
    ]);
    (hi, lo)
}

/// Pack `RPC_CMD_LOAD_TA` at [`RPC_COOKIE`]. Returns (cookie, bounce_len) covering MSG + tmem cap.
pub fn pack_load_ta(pool: &mut [u8], uuid: Uuid) -> Result<(u64, u32), ()> {
    let (hi, lo) = uuid_to_words(uuid);
    let dest = RPC_COOKIE + (MSG_ARG_HDR_SIZE + 2 * MSG_PARAM_SIZE) as u64;
    if dest % 8 != 0 || dest < RPC_COOKIE {
        return Err(());
    }
    let hdr = MsgArgHdr {
        cmd: RPC_CMD_LOAD_TA,
        num_params: 2,
        ..MsgArgHdr::default()
    };
    let params = [
        MsgParam::value(ATTR_TYPE_VALUE_INPUT, hi, lo, 0),
        MsgParam::tmem(ATTR_TYPE_TMEM_OUTPUT, dest, LOAD_TA_CAP, 0),
    ];
    write_msg(pool, RPC_COOKIE, hdr, &params).map_err(|_| ())?;
    let bounce_len = dest
        .checked_add(LOAD_TA_CAP)
        .and_then(|e| e.checked_sub(RPC_COOKIE))
        .ok_or(())? as u32;
    Ok((RPC_COOKIE, bounce_len))
}

/// ELF bytes from RPC_REPLY bounce param 1 (`TMEM_OUTPUT`). `params[1].a` is dest, `.b` is size.
pub fn take_load_ta(pool: &[u8]) -> Result<alloc::vec::Vec<u8>, u32> {
    let (hdr, params, _) = decode_msg(pool, RPC_COOKIE).map_err(|_| TEE_ERROR_BAD_PARAMETERS)?;
    if hdr.ret != 0 {
        return Err(hdr.ret);
    }
    if hdr.num_params < 2 {
        return Err(TEE_ERROR_BAD_PARAMETERS);
    }
    let dest = params[1].a as usize;
    let size = params[1].b as usize;
    let end = dest.checked_add(size).ok_or(TEE_ERROR_BAD_PARAMETERS)?;
    if dest < RPC_COOKIE as usize || end > pool.len() {
        return Err(TEE_ERROR_ITEM_NOT_FOUND);
    }
    Ok(pool[dest..end].to_vec())
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
