//! TEE_Panic aborts this TA instance. The kernel is not taken down.

pub fn tee_panic(code: u32) -> ! {
    #[cfg(target_os = "none")]
    {
        let _ = code;
        // TA abort. #[panic_handler] in the TA crate covers other panics.
        loop {
            #[cfg(target_arch = "aarch64")]
            unsafe {
                core::arch::asm!("wfe", options(nomem, nostack));
            }
            #[cfg(not(target_arch = "aarch64"))]
            core::hint::spin_loop();
        }
    }
    #[cfg(not(target_os = "none"))]
    panic!("TEE_Panic {code:#010x}");
}
