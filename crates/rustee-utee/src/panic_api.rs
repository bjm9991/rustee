//! TEE_Panic aborts this TA instance. The kernel is not taken down.

pub fn tee_panic(code: u32) -> ! {
    panic!("TEE_Panic {code:#010x}");
}
