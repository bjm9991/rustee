//! TEE_Malloc / Free / Realloc / Mem* / CheckMemoryAccessRights / instance data.

use crate::panic_api;
use crate::{TEE_ERROR_ACCESS_DENIED, TEE_SUCCESS, TeeResult};

pub const MALLOC_FILL_ZERO: u32 = 0;
pub const MALLOC_NO_FILL: u32 = 1;
pub const MALLOC_NO_SHARE: u32 = 2;
pub const ACCESS_READ: u32 = 1;
pub const ACCESS_WRITE: u32 = 2;
pub const ACCESS_ANY_OWNER: u32 = 4;

const HEAP_CAP: usize = 64 * 1024;
const HDR: usize = core::mem::size_of::<usize>();
const MAGIC: usize = 0x5554_4545; // 'UTEE'

pub struct Heap {
    buf: [u8; HEAP_CAP],
    used: usize,
    instance_data: usize,
}

impl Heap {
    pub const fn new() -> Self {
        Self {
            buf: [0; HEAP_CAP],
            used: 0,
            instance_data: 0,
        }
    }

    fn sentinel(&self) -> *mut u8 {
        self.buf.as_ptr().wrapping_add(HEAP_CAP) as *mut u8
    }

    fn is_sentinel(&self, p: *mut u8) -> bool {
        p == self.sentinel()
    }

    pub fn malloc(&mut self, size: usize, hint: u32) -> *mut u8 {
        if (hint & MALLOC_NO_FILL) != 0 && (hint & MALLOC_NO_SHARE) == 0 {
            panic_api::tee_panic(0);
        }
        if size == 0 {
            return self.sentinel();
        }
        let need = HDR.saturating_mul(2).saturating_add(size);
        let start = (self.used + 7) & !7;
        if start.saturating_add(need) > HEAP_CAP {
            return core::ptr::null_mut();
        }
        unsafe {
            let base = self.buf.as_mut_ptr().add(start);
            (base as *mut usize).write(MAGIC);
            (base.add(HDR) as *mut usize).write(size);
            let p = base.add(HDR * 2);
            if (hint & MALLOC_NO_FILL) == 0 {
                core::ptr::write_bytes(p, 0, size);
            }
            self.used = start + need;
            p
        }
    }

    fn size_of(&self, p: *mut u8) -> Option<usize> {
        if p.is_null() || self.is_sentinel(p) {
            return None;
        }
        unsafe {
            let base = p.sub(HDR * 2);
            let mag = (base as *const usize).read();
            if mag != MAGIC {
                return None;
            }
            Some((base.add(HDR) as *const usize).read())
        }
    }

    pub fn free(&mut self, p: *mut u8) {
        let _ = p;
    }

    pub fn realloc(&mut self, p: *mut u8, new_size: usize) -> *mut u8 {
        if p.is_null() {
            return self.malloc(new_size, MALLOC_FILL_ZERO);
        }
        if self.is_sentinel(p) {
            if new_size == 0 {
                return p;
            }
            return self.malloc(new_size, MALLOC_FILL_ZERO);
        }
        if new_size == 0 {
            self.free(p);
            return self.sentinel();
        }
        let old = self.size_of(p).unwrap_or(0);
        let n = self.malloc(new_size, MALLOC_FILL_ZERO);
        if n.is_null() {
            return core::ptr::null_mut();
        }
        let ncopy = core::cmp::min(old, new_size);
        if ncopy > 0 {
            unsafe { core::ptr::copy_nonoverlapping(p, n, ncopy) };
        }
        self.free(p);
        n
    }

    pub fn set_instance_data(&mut self, p: *mut u8) {
        self.instance_data = p as usize;
    }

    pub fn instance_data(&self) -> *mut u8 {
        self.instance_data as *mut u8
    }
}

pub fn mem_move(dest: *mut u8, src: *const u8, n: usize) {
    if n == 0 || dest.is_null() || src.is_null() {
        return;
    }
    unsafe { core::ptr::copy(src, dest, n) };
}

pub fn mem_fill(buf: *mut u8, x: u32, n: usize) {
    if n == 0 || buf.is_null() {
        return;
    }
    unsafe { core::ptr::write_bytes(buf, x as u8, n) };
}

pub fn mem_compare(a: *const u8, b: *const u8, n: usize) -> i32 {
    if n == 0 {
        return 0;
    }
    let mut diff = 0i32;
    for i in 0..n {
        let va = unsafe { *a.add(i) };
        let vb = unsafe { *b.add(i) };
        let d = va as i32 - vb as i32;
        let mask = ((diff == 0) as i32).wrapping_neg();
        diff |= d & mask;
    }
    diff.signum()
}

pub fn check_access(_flags: u32, buf: *mut u8, size: usize) -> TeeResult {
    if buf.is_null() && size != 0 {
        return TEE_ERROR_ACCESS_DENIED;
    }
    TEE_SUCCESS
}
