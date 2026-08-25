#![no_std]

use rustee_utee::param::Params;
use rustee_utee::{
    rustee_ta, Ta, TeeResult, TEE_ERROR_NOT_SUPPORTED, TEE_SUCCESS,
};

pub struct HelloTa;

fn echo_shm(params: &mut Params<'_>) -> TeeResult {
    match params.copy_memref(0, 1) {
        Ok(_) => TEE_SUCCESS,
        Err(e) => e,
    }
}

impl Ta for HelloTa {
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
        command_id: u32,
        params: &mut Params<'_>,
    ) -> TeeResult {
        match command_id {
            0 => echo_shm(params),
            _ => TEE_ERROR_NOT_SUPPORTED,
        }
    }
}

rustee_ta! {
    uuid: [0x8d, 0x82, 0x5f, 0x6a, 0x1c, 0x4b, 0x4c, 0x9f, 0x9e, 0x3a, 0x2b, 0x7c, 0x6d, 0x5e, 0x4f, 0x30],
    stack_size: 8192,
    data_size: 8192,
    single_instance: true,
    multi_session: false,
    instance_keep_alive: false,
    ta_version: 1,
    description: "hello-rs",
    version_str: "0.1.0",
    ta: HelloTa,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustee_utee::param::{Params, TeeParam};
    use rustee_utee::{
        param_types, TEE_ERROR_NOT_SUPPORTED, TEE_ERROR_SHORT_BUFFER, TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_SUCCESS,
    };

    #[test]
    fn cmd0_copies_bytes() {
        let mut src = *b"hello-rs";
        let mut dst = [0u8; 16];
        let mut slots = [
            TeeParam::memref(src.as_mut_ptr(), src.len()),
            TeeParam::memref(dst.as_mut_ptr(), dst.len()),
            TeeParam::none(),
            TeeParam::none(),
        ];
        let types = param_types(
            TEE_PARAM_TYPE_MEMREF_INPUT,
            TEE_PARAM_TYPE_MEMREF_OUTPUT,
            0,
            0,
        );
        let mut p = Params::from_slice(types, &mut slots);
        assert_eq!(
            HelloTa::invoke_command(core::ptr::null_mut(), 0, &mut p),
            TEE_SUCCESS
        );
        assert_eq!(&dst[..8], b"hello-rs");
        assert_eq!(p.memref_size(1), Some(8));
    }

    #[test]
    fn cmd0_short_buffer_sets_needed() {
        let mut src = *b"hello-rs";
        let mut dst = [0u8; 3];
        let mut slots = [
            TeeParam::memref(src.as_mut_ptr(), src.len()),
            TeeParam::memref(dst.as_mut_ptr(), dst.len()),
            TeeParam::none(),
            TeeParam::none(),
        ];
        let types = param_types(
            TEE_PARAM_TYPE_MEMREF_INPUT,
            TEE_PARAM_TYPE_MEMREF_OUTPUT,
            0,
            0,
        );
        let mut p = Params::from_slice(types, &mut slots);
        assert_eq!(
            HelloTa::invoke_command(core::ptr::null_mut(), 0, &mut p),
            TEE_ERROR_SHORT_BUFFER
        );
        assert_eq!(p.memref_size(1), Some(8));
    }

    #[test]
    fn other_cmd_not_supported() {
        let mut slots = [TeeParam::none(); 4];
        let mut p = Params::from_slice(0, &mut slots);
        assert_eq!(
            HelloTa::invoke_command(core::ptr::null_mut(), 99, &mut p),
            TEE_ERROR_NOT_SUPPORTED
        );
    }
}
