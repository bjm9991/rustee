//! Rust TA surface: `Ta` trait plus `rustee_ta!` (entry points + `.rustee.ta_head`).

use crate::param::{Params, TeeParam};
use crate::{TeeResult, TEE_NUM_PARAMS, TEE_SUCCESS};

pub trait Ta {
    fn create() -> TeeResult {
        TEE_SUCCESS
    }
    fn destroy() {}
    fn open_session(_params: &mut Params<'_>, _session_ctx: &mut *mut u8) -> TeeResult {
        TEE_SUCCESS
    }
    fn close_session(_session_ctx: *mut u8) {}
    fn invoke_command(
        _session_ctx: *mut u8,
        _command_id: u32,
        _params: &mut Params<'_>,
    ) -> TeeResult {
        TEE_SUCCESS
    }
}

/// Emit GP `TA_*` entry points and a 40-byte `.rustee.ta_head` (RTAH).
#[macro_export]
macro_rules! rustee_ta {
    (
        uuid: $uuid:expr,
        stack_size: $stack:expr,
        data_size: $data:expr,
        single_instance: $si:expr,
        multi_session: $ms:expr,
        instance_keep_alive: $ka:expr,
        ta_version: $ver:expr,
        description: $desc:expr,
        version_str: $vstr:expr,
        ta: $ta:ty $(,)?
    ) => {
        #[used]
        #[link_section = ".rustee.ta_head"]
        pub static RUSTEE_TA_HEAD: [u8; 40] = $crate::header::encode_ta_head(
            &$crate::header::TaProperties {
                uuid: $crate::kernel_abi::Uuid($uuid),
                stack_size: $stack,
                data_size: $data,
                single_instance: $si,
                multi_session: $ms,
                instance_keep_alive: $ka,
                endian: 0,
                ta_version: $ver,
            },
        );

        #[no_mangle]
        pub extern "C" fn TA_CreateEntryPoint() -> u32 {
            $crate::runtime::configure_ta(
                $crate::header::TaProperties {
                    uuid: $crate::kernel_abi::Uuid($uuid),
                    stack_size: $stack,
                    data_size: $data,
                    single_instance: $si,
                    multi_session: $ms,
                    instance_keep_alive: $ka,
                    endian: 0,
                    ta_version: $ver,
                },
                $vstr,
                $desc,
            );
            <$ta as $crate::ta::Ta>::create()
        }

        #[no_mangle]
        pub extern "C" fn TA_DestroyEntryPoint() {
            <$ta as $crate::ta::Ta>::destroy();
        }

        #[no_mangle]
        pub extern "C" fn TA_OpenSessionEntryPoint(
            param_types: u32,
            params: *mut $crate::param::TeeParam,
            session_ctx: *mut *mut u8,
        ) -> u32 {
            $crate::ta::open_entry::<$ta>(param_types, params, session_ctx)
        }

        #[no_mangle]
        pub extern "C" fn TA_CloseSessionEntryPoint(session_ctx: *mut u8) {
            <$ta as $crate::ta::Ta>::close_session(session_ctx);
        }

        #[no_mangle]
        pub extern "C" fn TA_InvokeCommandEntryPoint(
            session_ctx: *mut u8,
            command_id: u32,
            param_types: u32,
            params: *mut $crate::param::TeeParam,
        ) -> u32 {
            $crate::ta::invoke_entry::<$ta>(session_ctx, command_id, param_types, params)
        }
    };
}

pub fn open_entry<T: Ta>(
    param_types: u32,
    params: *mut TeeParam,
    session_ctx: *mut *mut u8,
) -> TeeResult {
    let mut dummy = [TeeParam::none(); TEE_NUM_PARAMS];
    let slots: &mut [TeeParam; TEE_NUM_PARAMS] = if params.is_null() {
        &mut dummy
    } else {
        unsafe { &mut *(params as *mut [TeeParam; TEE_NUM_PARAMS]) }
    };
    let mut p = Params::from_slice(param_types, slots);
    let mut ctx = core::ptr::null_mut();
    let r = T::open_session(&mut p, &mut ctx);
    if !session_ctx.is_null() {
        unsafe { *session_ctx = ctx };
    }
    r
}

pub fn invoke_entry<T: Ta>(
    session_ctx: *mut u8,
    command_id: u32,
    param_types: u32,
    params: *mut TeeParam,
) -> TeeResult {
    let mut dummy = [TeeParam::none(); TEE_NUM_PARAMS];
    let slots: &mut [TeeParam; TEE_NUM_PARAMS] = if params.is_null() {
        &mut dummy
    } else {
        unsafe { &mut *(params as *mut [TeeParam; TEE_NUM_PARAMS]) }
    };
    let mut p = Params::from_slice(param_types, slots);
    T::invoke_command(session_ctx, command_id, &mut p)
}
