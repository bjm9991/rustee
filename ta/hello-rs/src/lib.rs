#![cfg_attr(target_os = "none", no_std)]

extern crate alloc;

use rustee_utee::param::Params;
use rustee_utee::{rustee_ta, Ta, TeeResult, TEE_ERROR_NOT_SUPPORTED, TEE_SUCCESS};

/// TA lang items for aarch64-unknown-none. Host builds use std.
#[cfg(target_os = "none")]
mod ta_lang {
    use core::alloc::{GlobalAlloc, Layout};
    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicUsize, Ordering};

    const HEAP_LEN: usize = 32 * 1024;

    struct TaHeap {
        buf: UnsafeCell<[u8; HEAP_LEN]>,
        off: AtomicUsize,
    }
    unsafe impl Sync for TaHeap {}

    #[global_allocator]
    static HEAP: TaHeap = TaHeap {
        buf: UnsafeCell::new([0; HEAP_LEN]),
        off: AtomicUsize::new(0),
    };

    unsafe impl GlobalAlloc for TaHeap {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let a = layout.align().max(8);
            let size = layout.size();
            let mut off = self.off.load(Ordering::Relaxed);
            loop {
                let aligned = (off + a - 1) & !(a - 1);
                let next = aligned.saturating_add(size);
                if next > HEAP_LEN {
                    return core::ptr::null_mut();
                }
                match self
                    .off
                    .compare_exchange(off, next, Ordering::SeqCst, Ordering::Relaxed)
                {
                    Ok(_) => return (*self.buf.get()).as_mut_ptr().add(aligned),
                    Err(c) => off = c,
                }
            }
        }
        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
    }

    #[panic_handler]
    fn panic(_info: &core::panic::PanicInfo) -> ! {
        // TEE_Panic / abort kills this TA; the kernel is not taken down.
        loop {
            #[cfg(target_arch = "aarch64")]
            unsafe {
                core::arch::asm!("wfe", options(nomem, nostack));
            }
            #[cfg(not(target_arch = "aarch64"))]
            core::hint::spin_loop();
        }
    }
}

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
    use rustee_utee::header::RTAH_MAGIC;
    use rustee_utee::param::{Params, TeeParam};
    use rustee_utee::{
        param_types, TEE_ERROR_NOT_SUPPORTED, TEE_ERROR_SHORT_BUFFER, TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_SUCCESS,
    };

    extern crate std;
    use std::fs;
    use std::path::PathBuf;
    use std::vec::Vec;

    const HELLO_UUID: [u8; 16] = [
        0x8d, 0x82, 0x5f, 0x6a, 0x1c, 0x4b, 0x4c, 0x9f, 0x9e, 0x3a, 0x2b, 0x7c, 0x6d, 0x5e, 0x4f,
        0x30,
    ];

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

    #[test]
    fn rustee_ta_head_magic_rtah() {
        assert_eq!(
            u32::from_le_bytes(RUSTEE_TA_HEAD[0..4].try_into().unwrap()),
            RTAH_MAGIC
        );
        assert_eq!(RTAH_MAGIC, 0x4841_5452);
        assert_eq!(&RUSTEE_TA_HEAD[8..24], &HELLO_UUID);
        let _ = (
            TA_CreateEntryPoint as extern "C" fn() -> u32,
            TA_DestroyEntryPoint as extern "C" fn(),
            TA_OpenSessionEntryPoint as extern "C" fn(u32, *mut TeeParam, *mut *mut u8) -> u32,
            TA_CloseSessionEntryPoint as extern "C" fn(*mut u8),
            TA_InvokeCommandEntryPoint as extern "C" fn(*mut u8, u32, u32, *mut TeeParam) -> u32,
        );
    }

    fn hello_ta_path() -> PathBuf {
        if let Ok(p) = std::env::var("RUSTEE_HELLO_TA") {
            return PathBuf::from(p);
        }
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/hello-rs.ta")
    }

    fn u16le(b: &[u8], o: usize) -> u16 {
        u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
    }
    fn u32le(b: &[u8], o: usize) -> u32 {
        u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
    }
    fn u64le(b: &[u8], o: usize) -> u64 {
        u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
    }

    fn elf_str(tab: &[u8], off: usize) -> Option<&str> {
        let s = tab.get(off..)?;
        let end = s.iter().position(|&c| c == 0)?;
        core::str::from_utf8(&s[..end]).ok()
    }

    #[test]
    fn aarch64_elf_has_ta_head_and_symbols_if_built() {
        let path = hello_ta_path();
        if !path.exists() {
            return;
        }
        let bytes = fs::read(&path).unwrap();
        assert!(bytes.len() >= 64);
        assert_eq!(&bytes[0..4], b"\x7fELF");
        assert_eq!(bytes[4], 2, "ELF64");
        assert_eq!(bytes[5], 1, "LE");
        assert_eq!(u16le(&bytes, 18), 183, "EM_AARCH64");

        let shoff = u64le(&bytes, 40) as usize;
        let shentsize = u16le(&bytes, 58) as usize;
        let shnum = u16le(&bytes, 60) as usize;
        let shstrndx = u16le(&bytes, 62) as usize;
        let shstr = shoff + shstrndx * shentsize;
        let str_off = u64le(&bytes, shstr + 24) as usize;
        let str_size = u64le(&bytes, shstr + 32) as usize;
        let shstrtab = &bytes[str_off..str_off + str_size];

        let mut saw_head = false;
        let mut names: Vec<(&str, u64)> = Vec::new();
        for i in 0..shnum {
            let o = shoff + i * shentsize;
            let name_off = u32le(&bytes, o) as usize;
            let sh_type = u32le(&bytes, o + 4);
            let sec_off = u64le(&bytes, o + 24) as usize;
            let sec_size = u64le(&bytes, o + 32) as usize;
            let name = elf_str(shstrtab, name_off).unwrap_or("");
            if name == ".rustee.ta_head" {
                saw_head = true;
                assert!(sec_size >= 40);
                let head = &bytes[sec_off..sec_off + 40];
                assert_eq!(u32le(head, 0), 0x4841_5452);
                assert_eq!(&head[8..24], &HELLO_UUID);
            }
            if sh_type == 2 || sh_type == 11 {
                let sh_link = u32le(&bytes, o + 40) as usize;
                let ent = u64le(&bytes, o + 56) as usize;
                if ent == 0 {
                    continue;
                }
                let str_hdr = shoff + sh_link * shentsize;
                let so = u64le(&bytes, str_hdr + 24) as usize;
                let ss = u64le(&bytes, str_hdr + 32) as usize;
                let strtab = &bytes[so..so + ss];
                let n = sec_size / ent;
                for s in 0..n {
                    let e = sec_off + s * ent;
                    let no = u32le(&bytes, e) as usize;
                    let val = u64le(&bytes, e + 8);
                    if let Some(nm) = elf_str(strtab, no) {
                        names.push((nm, val));
                    }
                }
            }
        }
        assert!(saw_head, "missing .rustee.ta_head in {}", path.display());
        for want in [
            "TA_CreateEntryPoint",
            "TA_DestroyEntryPoint",
            "TA_OpenSessionEntryPoint",
            "TA_CloseSessionEntryPoint",
            "TA_InvokeCommandEntryPoint",
        ] {
            assert!(
                names.iter().any(|(n, v)| *n == want && *v != 0),
                "missing {want} in {}",
                path.display()
            );
        }
    }
}
