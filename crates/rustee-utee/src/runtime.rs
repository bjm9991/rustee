//! Per-TA instance state plus test hooks (syscall, time, entropy).

use crate::header::TaProperties;
use crate::kernel_abi::{KernelCmd, KernelOut, TeeSyscall};
use crate::mem::Heap;
use crate::param::{Identity, TeeTime};
use crate::property::{self, PropCtx};

const ENUM_SLOTS: usize = 4;
const SESSION_SLOTS: usize = 16;

#[derive(Clone, Copy)]
pub struct EnumSlot {
    pub used: bool,
    pub set: usize,
    pub idx: usize,
    pub started: bool,
}

impl EnumSlot {
    const fn empty() -> Self {
        Self {
            used: false,
            set: 0,
            idx: 0,
            started: false,
        }
    }
}

#[derive(Clone, Copy)]
pub struct PersistTime {
    pub set: bool,
    pub sys_base: TeeTime,
    pub value: TeeTime,
}

#[derive(Clone, Copy)]
struct SyscallHook {
    ptr: *mut (),
    call: Option<unsafe fn(*mut (), KernelCmd) -> KernelOut>,
}

#[derive(Clone, Copy)]
struct TimeHook {
    ptr: *mut (),
    system: Option<unsafe fn(*mut ()) -> TeeTime>,
    ree: Option<unsafe fn(*mut ()) -> TeeTime>,
    wait: Option<unsafe fn(*mut (), u32) -> crate::TeeResult>,
}

#[derive(Clone, Copy)]
struct EntropyHook {
    ptr: *mut (),
    fill: Option<unsafe fn(*mut (), *mut u8, usize)>,
}

pub trait TimeSource {
    fn system_time(&self) -> TeeTime;
    fn ree_time(&self) -> TeeTime;
    fn wait(&mut self, timeout_ms: u32) -> crate::TeeResult {
        let _ = timeout_ms;
        crate::TEE_SUCCESS
    }
}

/// Fill destination with TEE entropy. Do not treat host getrandom as TEE entropy.
pub trait Entropy {
    fn fill(&mut self, dest: &mut [u8]);
}

pub struct Core {
    pub heap: Heap,
    pub prop: PropCtx,
    pub cancel_masked: bool,
    pub cancel_flag: bool,
    pub next_cancel_id: u32,
    pub persist: PersistTime,
    sessions: [u32; SESSION_SLOTS],
    enums: [EnumSlot; ENUM_SLOTS],
    syscall: SyscallHook,
    time: TimeHook,
    entropy: EntropyHook,
}

impl Core {
    pub const fn new() -> Self {
        Self {
            heap: Heap::new(),
            prop: PropCtx::new(),
            cancel_masked: false,
            cancel_flag: false,
            next_cancel_id: 1,
            persist: PersistTime {
                set: false,
                sys_base: TeeTime {
                    seconds: 0,
                    millis: 0,
                },
                value: TeeTime {
                    seconds: 0,
                    millis: 0,
                },
            },
            sessions: [0; SESSION_SLOTS],
            enums: [EnumSlot::empty(); ENUM_SLOTS],
            syscall: SyscallHook {
                ptr: core::ptr::null_mut(),
                call: None,
            },
            time: TimeHook {
                ptr: core::ptr::null_mut(),
                system: None,
                ree: None,
                wait: None,
            },
            entropy: EntropyHook {
                ptr: core::ptr::null_mut(),
                fill: None,
            },
        }
    }
}

#[cfg(not(test))]
mod store {
    use super::Core;
    use core::cell::UnsafeCell;

    struct Cell(UnsafeCell<Core>);
    unsafe impl Sync for Cell {}
    static CORE: Cell = Cell(UnsafeCell::new(Core::new()));

    pub fn with<R>(f: impl FnOnce(&mut Core) -> R) -> R {
        f(unsafe { &mut *CORE.0.get() })
    }
}

#[cfg(test)]
mod store {
    use super::Core;
    use core::cell::RefCell;

    extern crate std;
    std::thread_local! {
        static CORE: RefCell<Core> = RefCell::new(Core::new());
    }

    pub fn with<R>(f: impl FnOnce(&mut Core) -> R) -> R {
        CORE.with(|c| f(&mut c.borrow_mut()))
    }
}

pub fn with_core<R>(f: impl FnOnce(&mut Core) -> R) -> R {
    store::with(f)
}

#[cfg(test)]
pub fn reset_for_test() {
    with_core(|c| *c = Core::new());
}

pub fn configure_ta(ta: TaProperties, version: &'static str, description: &'static str) {
    with_core(|c| {
        c.prop.ta = ta;
        c.prop.ta_version = version;
        c.prop.ta_description = description;
    });
}

pub fn set_client(id: Identity) {
    with_core(|c| c.prop.client = id);
}

pub fn caller_uuid() -> crate::kernel_abi::Uuid {
    with_core(|c| c.prop.ta.uuid)
}

pub fn mint_cancel_id() -> u32 {
    with_core(|c| {
        let id = c.next_cancel_id;
        c.next_cancel_id = c.next_cancel_id.wrapping_add(1).max(1);
        id
    })
}

pub fn cancellation_flag() -> bool {
    with_core(|c| c.cancel_flag)
}

pub fn set_cancellation_flag(v: bool) {
    with_core(|c| c.cancel_flag = v);
}

pub fn mask_cancellation() -> bool {
    with_core(|c| {
        let was_unmasked = !c.cancel_masked;
        c.cancel_masked = true;
        was_unmasked
    })
}

pub fn unmask_cancellation() -> bool {
    with_core(|c| {
        let was_unmasked = !c.cancel_masked;
        c.cancel_masked = false;
        was_unmasked
    })
}

pub fn cancellation_masked() -> bool {
    with_core(|c| c.cancel_masked)
}

pub fn syscall(cmd: KernelCmd) -> Option<KernelOut> {
    let hook = with_core(|c| c.syscall);
    hook.call.map(|f| unsafe { f(hook.ptr, cmd) })
}

pub fn system_time() -> TeeTime {
    let hook = with_core(|c| c.time);
    match hook.system {
        Some(f) => unsafe { f(hook.ptr) },
        None => TeeTime {
            seconds: 0,
            millis: 0,
        },
    }
}

pub fn ree_time() -> TeeTime {
    let hook = with_core(|c| c.time);
    match hook.ree {
        Some(f) => unsafe { f(hook.ptr) },
        None => TeeTime {
            seconds: 0,
            millis: 0,
        },
    }
}

pub fn time_wait(timeout_ms: u32) -> crate::TeeResult {
    let hook = with_core(|c| c.time);
    match hook.wait {
        Some(f) => unsafe { f(hook.ptr, timeout_ms) },
        None => crate::TEE_SUCCESS,
    }
}

pub fn fill_entropy(dest: &mut [u8]) {
    let hook = with_core(|c| c.entropy);
    match hook.fill {
        Some(f) => unsafe { f(hook.ptr, dest.as_mut_ptr(), dest.len()) },
        None => dest.fill(0),
    }
}

pub fn persist() -> PersistTime {
    with_core(|c| c.persist)
}

pub fn set_persist(p: PersistTime) {
    with_core(|c| c.persist = p);
}

pub fn malloc(size: usize, hint: u32) -> *mut u8 {
    with_core(|c| c.heap.malloc(size, hint))
}

pub fn free(p: *mut u8) {
    with_core(|c| c.heap.free(p));
}

pub fn realloc(p: *mut u8, new_size: usize) -> *mut u8 {
    with_core(|c| c.heap.realloc(p, new_size))
}

pub fn set_instance_data(p: *mut u8) {
    with_core(|c| c.heap.set_instance_data(p));
}

pub fn instance_data() -> *mut u8 {
    with_core(|c| c.heap.instance_data())
}

pub fn remember_session(id: u32) -> bool {
    with_core(|c| {
        for s in c.sessions.iter_mut() {
            if *s == 0 {
                *s = id;
                return true;
            }
        }
        false
    })
}

pub fn forget_session(id: u32) -> bool {
    with_core(|c| {
        for s in c.sessions.iter_mut() {
            if *s == id {
                *s = 0;
                return true;
            }
        }
        false
    })
}

pub fn has_session(id: u32) -> bool {
    with_core(|c| c.sessions.iter().any(|s| *s == id))
}

pub fn alloc_enumerator() -> Option<usize> {
    with_core(|c| {
        for (i, e) in c.enums.iter_mut().enumerate() {
            if !e.used {
                *e = EnumSlot {
                    used: true,
                    set: 0,
                    idx: 0,
                    started: false,
                };
                return Some(i + 1);
            }
        }
        None
    })
}

pub fn free_enumerator(h: usize) {
    with_core(|c| {
        if let Some(e) = slot_mut(c, h) {
            *e = EnumSlot::empty();
        }
    });
}

fn slot_mut(c: &mut Core, h: usize) -> Option<&mut EnumSlot> {
    if h == 0 {
        return None;
    }
    c.enums.get_mut(h - 1).filter(|e| e.used)
}

pub fn start_enumerator(h: usize, set: usize) -> bool {
    with_core(|c| {
        if let Some(e) = slot_mut(c, h) {
            e.set = set;
            e.idx = 0;
            e.started = true;
            true
        } else {
            false
        }
    })
}

pub fn reset_enumerator(h: usize) {
    with_core(|c| {
        if let Some(e) = slot_mut(c, h) {
            e.idx = 0;
        }
    });
}

pub fn enumerator_name(h: usize) -> Result<&'static str, crate::TeeResult> {
    with_core(|c| {
        let e = slot_mut(c, h).ok_or(crate::TEE_ERROR_ITEM_NOT_FOUND)?;
        if !e.started {
            return Err(crate::TEE_ERROR_ITEM_NOT_FOUND);
        }
        property::name_at(e.set, e.idx).ok_or(crate::TEE_ERROR_ITEM_NOT_FOUND)
    })
}

pub fn enumerator_next(h: usize) -> crate::TeeResult {
    with_core(|c| {
        let e = match slot_mut(c, h) {
            Some(e) if e.started => e,
            _ => return crate::TEE_ERROR_ITEM_NOT_FOUND,
        };
        e.idx = e.idx.saturating_add(1);
        if property::name_at(e.set, e.idx).is_some() {
            crate::TEE_SUCCESS
        } else {
            crate::TEE_ERROR_ITEM_NOT_FOUND
        }
    })
}

pub fn enumerator_current(h: usize) -> Result<(usize, &'static str), crate::TeeResult> {
    with_core(|c| {
        let e = slot_mut(c, h).ok_or(crate::TEE_ERROR_ITEM_NOT_FOUND)?;
        if !e.started {
            return Err(crate::TEE_ERROR_ITEM_NOT_FOUND);
        }
        let n = property::name_at(e.set, e.idx).ok_or(crate::TEE_ERROR_ITEM_NOT_FOUND)?;
        Ok((e.set, n))
    })
}


unsafe fn syscall_shim<S: TeeSyscall>(ptr: *mut (), cmd: KernelCmd) -> KernelOut {
    (*(ptr as *mut S)).handle(cmd)
}

unsafe fn time_system_shim<T: TimeSource>(ptr: *mut ()) -> TeeTime {
    (*(ptr as *mut T)).system_time()
}

unsafe fn time_ree_shim<T: TimeSource>(ptr: *mut ()) -> TeeTime {
    (*(ptr as *mut T)).ree_time()
}

unsafe fn time_wait_shim<T: TimeSource>(ptr: *mut (), timeout_ms: u32) -> crate::TeeResult {
    (*(ptr as *mut T)).wait(timeout_ms)
}

unsafe fn entropy_shim<E: Entropy>(ptr: *mut (), dest: *mut u8, len: usize) {
    let sl = core::slice::from_raw_parts_mut(dest, len);
    (*(ptr as *mut E)).fill(sl);
}

pub fn with_syscall<S: TeeSyscall, R>(s: &mut S, f: impl FnOnce() -> R) -> R {
    let prev = with_core(|c| {
        let old = c.syscall;
        c.syscall = SyscallHook {
            ptr: s as *mut S as *mut (),
            call: Some(syscall_shim::<S>),
        };
        old
    });
    struct Guard(SyscallHook);
    impl Drop for Guard {
        fn drop(&mut self) {
            with_core(|c| c.syscall = self.0);
        }
    }
    let _g = Guard(prev);
    f()
}

pub fn with_time<T: TimeSource, R>(t: &mut T, f: impl FnOnce() -> R) -> R {
    let prev = with_core(|c| {
        let old = c.time;
        c.time = TimeHook {
            ptr: t as *mut T as *mut (),
            system: Some(time_system_shim::<T>),
            ree: Some(time_ree_shim::<T>),
            wait: Some(time_wait_shim::<T>),
        };
        old
    });
    struct Guard(TimeHook);
    impl Drop for Guard {
        fn drop(&mut self) {
            with_core(|c| c.time = self.0);
        }
    }
    let _g = Guard(prev);
    f()
}

pub fn with_entropy<E: Entropy, R>(e: &mut E, f: impl FnOnce() -> R) -> R {
    let prev = with_core(|c| {
        let old = c.entropy;
        c.entropy = EntropyHook {
            ptr: e as *mut E as *mut (),
            fill: Some(entropy_shim::<E>),
        };
        old
    });
    struct Guard(EntropyHook);
    impl Drop for Guard {
        fn drop(&mut self) {
            with_core(|c| c.entropy = self.0);
        }
    }
    let _g = Guard(prev);
    f()
}
