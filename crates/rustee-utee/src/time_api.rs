//! Time API. TimeSource is injected so tests do not need a HAL.

use crate::param::TeeTime;
use crate::runtime::{self, PersistTime};
use crate::{
    TEE_ERROR_BAD_PARAMETERS, TEE_ERROR_CANCEL, TEE_ERROR_OVERFLOW, TEE_ERROR_TIME_NOT_SET,
    TEE_SUCCESS, TeeResult,
};

fn add(base: TeeTime, delta: TeeTime) -> Result<TeeTime, TeeResult> {
    let mut ms = base.millis as u64 + delta.millis as u64;
    let extra = ms / 1000;
    ms %= 1000;
    let sec = (base.seconds as u64)
        .checked_add(delta.seconds as u64)
        .and_then(|s| s.checked_add(extra))
        .ok_or(TEE_ERROR_OVERFLOW)?;
    if sec > u32::MAX as u64 {
        return Err(TEE_ERROR_OVERFLOW);
    }
    Ok(TeeTime {
        seconds: sec as u32,
        millis: ms as u32,
    })
}

fn sat_sub(later: TeeTime, earlier: TeeTime) -> TeeTime {
    let mut ms = later.millis as i64 - earlier.millis as i64;
    let mut sec = later.seconds as i64 - earlier.seconds as i64;
    if ms < 0 {
        ms += 1000;
        sec -= 1;
    }
    if sec < 0 {
        TeeTime {
            seconds: 0,
            millis: 0,
        }
    } else {
        TeeTime {
            seconds: sec as u32,
            millis: ms as u32,
        }
    }
}

pub fn get_system_time(time: *mut TeeTime) {
    if time.is_null() {
        crate::panic_api::tee_panic(TEE_ERROR_BAD_PARAMETERS);
    }
    unsafe { *time = runtime::system_time() };
}

pub fn get_ree_time(time: *mut TeeTime) {
    if time.is_null() {
        crate::panic_api::tee_panic(TEE_ERROR_BAD_PARAMETERS);
    }
    unsafe { *time = runtime::ree_time() };
}

pub fn wait(timeout_ms: u32) -> TeeResult {
    if !runtime::cancellation_masked() && runtime::cancellation_flag() {
        return TEE_ERROR_CANCEL;
    }
    if timeout_ms == 0 {
        return TEE_SUCCESS;
    }
    runtime::time_wait(timeout_ms)
}

pub fn get_ta_persistent_time(time: *mut TeeTime) -> TeeResult {
    if time.is_null() {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    let p = runtime::persist();
    if !p.set {
        return TEE_ERROR_TIME_NOT_SET;
    }
    let now = runtime::system_time();
    let elapsed = sat_sub(now, p.sys_base);
    match add(p.value, elapsed) {
        Ok(t) => {
            unsafe { *time = t };
            TEE_SUCCESS
        }
        Err(e) => e,
    }
}

pub fn set_ta_persistent_time(time: *const TeeTime) -> TeeResult {
    if time.is_null() {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    let t = unsafe { *time };
    if t.millis >= 1000 {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    runtime::set_persist(PersistTime {
        set: true,
        sys_base: runtime::system_time(),
        value: t,
    });
    TEE_SUCCESS
}
