#![no_std]

use rustee_utee::param::Params;
use rustee_utee::{rustee_ta, Ta, TeeResult, TEE_SUCCESS};

pub struct HelloTa;

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
        _command_id: u32,
        _params: &mut Params<'_>,
    ) -> TeeResult {
        TEE_SUCCESS
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
