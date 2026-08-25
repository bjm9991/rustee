//! `#[no_mangle] extern "C"` for every prototype in tee_internal_api.h we implement.

use crate::param::{TeeIdentity, TeeObjectInfo, TeeParam, TeeTime, TeeUuid};
use crate::property::{self, PROPSET_CLIENT, PROPSET_TA, PROPSET_TEE};
use crate::runtime;
use crate::{
    TEE_ERROR_BAD_PARAMETERS, TEE_ERROR_NOT_SUPPORTED, TEE_ERROR_OUT_OF_MEMORY,
    TEE_ERROR_SHORT_BUFFER, TEE_SUCCESS, TEE_TYPE_DATA, TeeResult,
};
use core::ffi::{c_char, c_void, CStr};

pub type TeePropSetHandle = *mut c_void;
pub type TeeTaSessionHandle = *mut c_void;
pub type TeeObjectEnumHandle = *mut c_void;

fn handle_us(h: TeePropSetHandle) -> usize {
    h as usize
}

fn cstr<'a>(p: *const c_char) -> Result<&'a str, TeeResult> {
    if p.is_null() {
        return Err(TEE_ERROR_BAD_PARAMETERS);
    }
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|_| TEE_ERROR_BAD_PARAMETERS)
}

fn write_buf(src: &str, buf: *mut c_char, len: *mut usize) -> TeeResult {
    if len.is_null() {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    let need = src.len() + 1;
    let cap = unsafe { *len };
    unsafe { *len = need };
    if buf.is_null() || cap < need {
        return crate::TEE_ERROR_SHORT_BUFFER;
    }
    let out = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, cap) };
    match property::copy_str(src, out) {
        Ok(_) => TEE_SUCCESS,
        Err(e) => e,
    }
}

fn resolve(handle: usize, name: *const c_char) -> Result<(usize, alloc::string::String), TeeResult> {
    if property::is_propset(handle) {
        let n = cstr(name)?;
        Ok((handle, alloc::string::String::from(n)))
    } else {
        let (set, n) = runtime::enumerator_current(handle)?;
        Ok((set, alloc::string::String::from(n)))
    }
}

#[no_mangle]
pub extern "C" fn TEE_GetPropertyAsString(
    propset_or_enumerator: TeePropSetHandle,
    name: *const c_char,
    value_buffer: *mut c_char,
    value_buffer_len: *mut usize,
) -> TeeResult {
    let (set, n) = match resolve(handle_us(propset_or_enumerator), name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    runtime::with_core(|c| match property::get_str(&c.prop, set, &n) {
        Ok(s) => write_buf(s, value_buffer, value_buffer_len),
        Err(e) => e,
    })
}

#[no_mangle]
pub extern "C" fn TEE_GetPropertyAsBool(
    propset_or_enumerator: TeePropSetHandle,
    name: *const c_char,
    value: *mut bool,
) -> TeeResult {
    if value.is_null() {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    let (set, n) = match resolve(handle_us(propset_or_enumerator), name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    runtime::with_core(|c| match property::get_bool(&c.prop, set, &n) {
        Ok(v) => {
            unsafe { *value = v };
            TEE_SUCCESS
        }
        Err(e) => e,
    })
}

#[no_mangle]
pub extern "C" fn TEE_GetPropertyAsU32(
    propset_or_enumerator: TeePropSetHandle,
    name: *const c_char,
    value: *mut u32,
) -> TeeResult {
    if value.is_null() {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    let (set, n) = match resolve(handle_us(propset_or_enumerator), name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    runtime::with_core(|c| match property::get_u32(&c.prop, set, &n) {
        Ok(v) => {
            unsafe { *value = v };
            TEE_SUCCESS
        }
        Err(e) => e,
    })
}

#[no_mangle]
pub extern "C" fn TEE_GetPropertyAsU64(
    propset_or_enumerator: TeePropSetHandle,
    name: *const c_char,
    value: *mut u64,
) -> TeeResult {
    if value.is_null() {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    let (set, n) = match resolve(handle_us(propset_or_enumerator), name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    runtime::with_core(|c| match property::get_u64(&c.prop, set, &n) {
        Ok(v) => {
            unsafe { *value = v };
            TEE_SUCCESS
        }
        Err(e) => e,
    })
}

#[no_mangle]
pub extern "C" fn TEE_GetPropertyAsBinaryBlock(
    propset_or_enumerator: TeePropSetHandle,
    name: *const c_char,
    value_buffer: *mut c_void,
    value_buffer_len: *mut usize,
) -> TeeResult {
    if value_buffer_len.is_null() {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    let (set, n) = match resolve(handle_us(propset_or_enumerator), name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let cap = unsafe { *value_buffer_len };
    let mut tmp = [0u8; 256];
    let ncopy = runtime::with_core(|c| property::binary_of(&c.prop, set, &n, &mut tmp));
    match ncopy {
        Ok(need) => {
            unsafe { *value_buffer_len = need };
            if value_buffer.is_null() || cap < need {
                return crate::TEE_ERROR_SHORT_BUFFER;
            }
            unsafe {
                core::ptr::copy_nonoverlapping(tmp.as_ptr(), value_buffer as *mut u8, need);
            }
            TEE_SUCCESS
        }
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn TEE_GetPropertyAsUUID(
    propset_or_enumerator: TeePropSetHandle,
    name: *const c_char,
    value: *mut TeeUuid,
) -> TeeResult {
    if value.is_null() {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    let (set, n) = match resolve(handle_us(propset_or_enumerator), name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    runtime::with_core(|c| match property::get_uuid(&c.prop, set, &n) {
        Ok(u) => {
            unsafe { *value = TeeUuid::from_uuid(u) };
            TEE_SUCCESS
        }
        Err(e) => e,
    })
}

#[no_mangle]
pub extern "C" fn TEE_GetPropertyAsIdentity(
    propset_or_enumerator: TeePropSetHandle,
    name: *const c_char,
    value: *mut TeeIdentity,
) -> TeeResult {
    if value.is_null() {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    let (set, n) = match resolve(handle_us(propset_or_enumerator), name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    runtime::with_core(|c| match property::get_identity(&c.prop, set, &n) {
        Ok(id) => {
            unsafe {
                *value = TeeIdentity {
                    login: id.login,
                    uuid: TeeUuid::from_uuid(id.uuid),
                };
            }
            TEE_SUCCESS
        }
        Err(e) => e,
    })
}

#[no_mangle]
pub extern "C" fn TEE_AllocatePropertyEnumerator(enumerator: *mut TeePropSetHandle) -> TeeResult {
    if enumerator.is_null() {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    match runtime::alloc_enumerator() {
        Some(h) => {
            unsafe { *enumerator = h as TeePropSetHandle };
            TEE_SUCCESS
        }
        None => TEE_ERROR_OUT_OF_MEMORY,
    }
}

#[no_mangle]
pub extern "C" fn TEE_FreePropertyEnumerator(enumerator: TeePropSetHandle) {
    runtime::free_enumerator(handle_us(enumerator));
}

#[no_mangle]
pub extern "C" fn TEE_StartPropertyEnumerator(
    enumerator: TeePropSetHandle,
    prop_set: TeePropSetHandle,
) {
    let set = handle_us(prop_set);
    if set == PROPSET_TA || set == PROPSET_CLIENT || set == PROPSET_TEE {
        runtime::start_enumerator(handle_us(enumerator), set);
    }
}

#[no_mangle]
pub extern "C" fn TEE_ResetPropertyEnumerator(enumerator: TeePropSetHandle) {
    runtime::reset_enumerator(handle_us(enumerator));
}

#[no_mangle]
pub extern "C" fn TEE_GetPropertyName(
    enumerator: TeePropSetHandle,
    name_buffer: *mut c_void,
    name_buffer_len: *mut usize,
) -> TeeResult {
    match runtime::enumerator_name(handle_us(enumerator)) {
        Ok(n) => write_buf(n, name_buffer as *mut c_char, name_buffer_len),
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn TEE_GetNextProperty(enumerator: TeePropSetHandle) -> TeeResult {
    runtime::enumerator_next(handle_us(enumerator))
}

#[no_mangle]
pub extern "C" fn TEE_Panic(panic_code: TeeResult) -> ! {
    crate::panic_api::tee_panic(panic_code)
}

#[no_mangle]
pub extern "C" fn TEE_OpenTASession(
    destination: *const TeeUuid,
    cancellation_request_timeout: u32,
    param_types: u32,
    params: *mut TeeParam,
    session: *mut TeeTaSessionHandle,
    return_origin: *mut u32,
) -> TeeResult {
    crate::client::open_ta_session(
        destination,
        cancellation_request_timeout,
        param_types,
        params,
        session,
        return_origin,
    )
}

#[no_mangle]
pub extern "C" fn TEE_CloseTASession(session: TeeTaSessionHandle) {
    crate::client::close_ta_session(session);
}

#[no_mangle]
pub extern "C" fn TEE_InvokeTACommand(
    session: TeeTaSessionHandle,
    cancellation_request_timeout: u32,
    command_id: u32,
    param_types: u32,
    params: *mut TeeParam,
    return_origin: *mut u32,
) -> TeeResult {
    crate::client::invoke_ta_command(
        session,
        cancellation_request_timeout,
        command_id,
        param_types,
        params,
        return_origin,
    )
}

#[no_mangle]
pub extern "C" fn TEE_GetCancellationFlag() -> bool {
    runtime::cancellation_flag()
}

#[no_mangle]
pub extern "C" fn TEE_UnmaskCancellation() -> bool {
    runtime::unmask_cancellation()
}

#[no_mangle]
pub extern "C" fn TEE_MaskCancellation() -> bool {
    runtime::mask_cancellation()
}

#[no_mangle]
pub extern "C" fn TEE_CheckMemoryAccessRights(
    access_flags: u32,
    buffer: *mut c_void,
    size: usize,
) -> TeeResult {
    crate::mem::check_access(access_flags, buffer as *mut u8, size)
}

#[no_mangle]
pub extern "C" fn TEE_SetInstanceData(instance_data: *mut c_void) {
    runtime::set_instance_data(instance_data as *mut u8);
}

#[no_mangle]
pub extern "C" fn TEE_GetInstanceData() -> *mut c_void {
    runtime::instance_data() as *mut c_void
}

#[no_mangle]
pub extern "C" fn TEE_Malloc(size: usize, hint: u32) -> *mut c_void {
    runtime::malloc(size, hint) as *mut c_void
}

#[no_mangle]
pub extern "C" fn TEE_Realloc(buffer: *mut c_void, new_size: usize) -> *mut c_void {
    runtime::realloc(buffer as *mut u8, new_size) as *mut c_void
}

#[no_mangle]
pub extern "C" fn TEE_Free(buffer: *mut c_void) {
    runtime::free(buffer as *mut u8);
}

#[no_mangle]
pub extern "C" fn TEE_MemMove(dest: *mut c_void, src: *const c_void, size: usize) {
    crate::mem::mem_move(dest as *mut u8, src as *const u8, size);
}

#[no_mangle]
pub extern "C" fn TEE_MemCompare(buffer1: *const c_void, buffer2: *const c_void, size: usize) -> i32 {
    crate::mem::mem_compare(buffer1 as *const u8, buffer2 as *const u8, size)
}

#[no_mangle]
pub extern "C" fn TEE_MemFill(buff: *mut c_void, x: u32, size: usize) {
    crate::mem::mem_fill(buff as *mut u8, x, size);
}

#[no_mangle]
pub extern "C" fn TEE_GetSystemTime(time: *mut TeeTime) {
    crate::time_api::get_system_time(time);
}

#[no_mangle]
pub extern "C" fn TEE_Wait(timeout: u32) -> TeeResult {
    crate::time_api::wait(timeout)
}

#[no_mangle]
pub extern "C" fn TEE_GetTAPersistentTime(time: *mut TeeTime) -> TeeResult {
    crate::time_api::get_ta_persistent_time(time)
}

#[no_mangle]
pub extern "C" fn TEE_SetTAPersistentTime(time: *const TeeTime) -> TeeResult {
    crate::time_api::set_ta_persistent_time(time)
}

#[no_mangle]
pub extern "C" fn TEE_GetREETime(time: *mut TeeTime) {
    crate::time_api::get_ree_time(time);
}

#[no_mangle]
pub extern "C" fn TEE_IsAlgorithmSupported(alg_id: u32, element: u32) -> TeeResult {
    if crate::crypto_api::is_algorithm_supported(alg_id, element) {
        TEE_SUCCESS
    } else {
        TEE_ERROR_NOT_SUPPORTED
    }
}

#[no_mangle]
pub extern "C" fn TEE_GenerateRandom(random_buffer: *mut c_void, random_buffer_len: usize) {
    crate::crypto_api::generate_random(random_buffer as *mut u8, random_buffer_len);
}

#[no_mangle]
pub extern "C" fn TEE_BigIntFMMSizeInU32(modulus_size_in_bits: usize) -> usize {
    crate::arith::big_int_fmm_size_in_u32(modulus_size_in_bits)
}

#[no_mangle]
pub extern "C" fn TEE_BigIntFMMContextSizeInU32(modulus_size_in_bits: usize) -> usize {
    crate::arith::big_int_fmm_context_size_in_u32(modulus_size_in_bits)
}

#[no_mangle]
pub extern "C" fn TEE_BigIntInit(big_int: *mut u32, len: usize) {
    crate::arith::big_int_init(big_int, len);
}

#[no_mangle]
pub extern "C" fn TEE_BigIntInitFMMContext1(
    context: *mut u32,
    len: usize,
    modulus: *const u32,
) -> TeeResult {
    crate::arith::big_int_init_fmm_context1(context, len, modulus)
}

#[no_mangle]
pub extern "C" fn TEE_BigIntInitFMMContext(context: *mut u32, len: usize, modulus: *const u32) {
    crate::arith::big_int_init_fmm_context(context, len, modulus);
}

#[no_mangle]
pub extern "C" fn TEE_BigIntInitFMM(big_int_fmm: *mut u32, len: usize) {
    crate::arith::big_int_init_fmm(big_int_fmm, len);
}


#[no_mangle]
pub extern "C" fn TEE_AllocatePersistentObjectEnumerator(
    enumerator: *mut TeeObjectEnumHandle,
) -> TeeResult {
    if enumerator.is_null() {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    match runtime::alloc_object_enumerator() {
        Some(h) => {
            unsafe { *enumerator = h as TeeObjectEnumHandle };
            TEE_SUCCESS
        }
        None => TEE_ERROR_OUT_OF_MEMORY,
    }
}

#[no_mangle]
pub extern "C" fn TEE_FreePersistentObjectEnumerator(enumerator: TeeObjectEnumHandle) {
    runtime::free_object_enumerator(enumerator as usize);
}

#[no_mangle]
pub extern "C" fn TEE_ResetPersistentObjectEnumerator(enumerator: TeeObjectEnumHandle) {
    runtime::reset_object_enumerator(enumerator as usize);
}

#[no_mangle]
pub extern "C" fn TEE_StartPersistentObjectEnumerator(
    enumerator: TeeObjectEnumHandle,
    storage_id: u32,
) -> TeeResult {
    runtime::start_object_enumerator(enumerator as usize, storage_id)
}

#[no_mangle]
pub extern "C" fn TEE_GetNextPersistentObject(
    enumerator: TeeObjectEnumHandle,
    object_info: *mut TeeObjectInfo,
    object_id: *mut c_void,
    object_id_len: *mut usize,
) -> TeeResult {
    if object_id_len.is_null() {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    let item = match runtime::object_enum_peek(enumerator as usize) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let need = item.object_id.len();
    let cap = unsafe { *object_id_len };
    unsafe { *object_id_len = need };
    if object_id.is_null() || cap < need {
        return TEE_ERROR_SHORT_BUFFER;
    }
    if need != 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(item.object_id.as_ptr(), object_id as *mut u8, need);
        }
    }
    if !object_info.is_null() {
        unsafe {
            *object_info = TeeObjectInfo {
                object_type: TEE_TYPE_DATA,
                object_size: 0,
                max_object_size: 0,
                object_usage: 0,
                data_size: item.data_size as usize,
                data_position: 0,
                handle_flags: item.flags,
            };
        }
    }
    runtime::object_enum_advance(enumerator as usize);
    TEE_SUCCESS
}

pub fn propset_ta() -> TeePropSetHandle {
    PROPSET_TA as TeePropSetHandle
}
pub fn propset_client() -> TeePropSetHandle {
    PROPSET_CLIENT as TeePropSetHandle
}
pub fn propset_tee() -> TeePropSetHandle {
    PROPSET_TEE as TeePropSetHandle
}

