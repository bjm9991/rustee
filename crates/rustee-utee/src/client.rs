//! Internal Client API: TEE_OpenTASession / InvokeTACommand / CloseTASession.

use crate::kernel_abi::{KernelCmd, KernelOut, Login, Origin, SessionId};
use crate::param::{copy_out, params_from_gp, TeeParam, TeeUuid};
use crate::runtime;
use crate::{
    TEE_ERROR_BAD_PARAMETERS, TEE_ERROR_NOT_IMPLEMENTED, TEE_ERROR_TARGET_DEAD, TEE_ORIGIN_API,
    TEE_SUCCESS, TeeResult,
};

pub type SessionHandle = *mut core::ffi::c_void;

fn handle_from_id(id: SessionId) -> SessionHandle {
    id.0 as usize as SessionHandle
}

fn id_from_handle(h: SessionHandle) -> u32 {
    h as usize as u32
}

fn map_origin(o: Origin) -> u32 {
    o.as_gp()
}

fn write_origin(p: *mut u32, origin: u32) {
    if !p.is_null() {
        unsafe { *p = origin };
    }
}

pub fn open_ta_session(
    dest: *const TeeUuid,
    timeout_ms: u32,
    param_types: u32,
    params: *mut TeeParam,
    session: *mut SessionHandle,
    return_origin: *mut u32,
) -> TeeResult {
    if dest.is_null() || session.is_null() {
        write_origin(return_origin, TEE_ORIGIN_API);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    let params_abi = match params_from_gp(param_types, params) {
        Ok(p) => p,
        Err(e) => {
            write_origin(return_origin, TEE_ORIGIN_API);
            unsafe { *session = core::ptr::null_mut() };
            return e;
        }
    };
    let uuid = unsafe { (*dest).to_uuid() };
    let cancel_id = runtime::mint_cancel_id();
    let login = Login::TrustedApp {
        uuid: runtime::caller_uuid(),
    };
    let cmd = KernelCmd::OpenSession {
        uuid,
        login,
        params: params_abi,
        cancel_id,
        timeout_ms,
    };
    let out = match runtime::syscall(cmd) {
        Some(o) => o,
        None => {
            write_origin(return_origin, TEE_ORIGIN_API);
            unsafe { *session = core::ptr::null_mut() };
            return TEE_ERROR_NOT_IMPLEMENTED;
        }
    };
    match out {
        KernelOut::Done {
            result,
            session: sid,
            params: produced,
        } => {
            copy_out(param_types, params, &produced);
            write_origin(return_origin, map_origin(result.origin));
            if result.code == TEE_SUCCESS {
                match sid {
                    Some(id) if !id.is_null() => {
                        runtime::remember_session(id.0);
                        unsafe { *session = handle_from_id(id) };
                    }
                    _ => {
                        unsafe { *session = core::ptr::null_mut() };
                        write_origin(return_origin, TEE_ORIGIN_API);
                        return TEE_ERROR_BAD_PARAMETERS;
                    }
                }
            } else {
                unsafe { *session = core::ptr::null_mut() };
            }
            result.code
        }
    }
}

pub fn close_ta_session(session: SessionHandle) {
    if session.is_null() {
        return;
    }
    let id = id_from_handle(session);
    if id == 0 || !runtime::has_session(id) {
        crate::panic_api::tee_panic(TEE_ERROR_TARGET_DEAD);
    }
    let _ = runtime::syscall(KernelCmd::CloseSession {
        session: SessionId(id),
    });
    runtime::forget_session(id);
}

pub fn invoke_ta_command(
    session: SessionHandle,
    timeout_ms: u32,
    command_id: u32,
    param_types: u32,
    params: *mut TeeParam,
    return_origin: *mut u32,
) -> TeeResult {
    if session.is_null() {
        write_origin(return_origin, TEE_ORIGIN_API);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    let id = id_from_handle(session);
    if id == 0 || !runtime::has_session(id) {
        crate::panic_api::tee_panic(TEE_ERROR_TARGET_DEAD);
    }
    let params_abi = match params_from_gp(param_types, params) {
        Ok(p) => p,
        Err(e) => {
            write_origin(return_origin, TEE_ORIGIN_API);
            return e;
        }
    };
    let cancel_id = runtime::mint_cancel_id();
    let cmd = KernelCmd::Invoke {
        session: SessionId(id),
        cmd_id: command_id,
        params: params_abi,
        cancel_id,
        timeout_ms,
    };
    let out = match runtime::syscall(cmd) {
        Some(o) => o,
        None => {
            write_origin(return_origin, TEE_ORIGIN_API);
            return TEE_ERROR_NOT_IMPLEMENTED;
        }
    };
    match out {
        KernelOut::Done {
            result,
            params: produced,
            ..
        } => {
            copy_out(param_types, params, &produced);
            write_origin(return_origin, map_origin(result.origin));
            result.code
        }
    }
}
