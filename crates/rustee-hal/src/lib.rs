#![no_std]
//! Isolation HAL. `Kernel<H: rustee_hal::Hal, C: CryptoProvider>`.
//! Trait is [`Hal`], not Backend. Public types are ISA-neutral: no TTBR, SMC,
//! SBI, vsock, or sockets. Kernel does not speak MSG and does not call `Hal::rpc`.
//!
//! Inbound: [`CallGate::recv`] → proto → `Kernel::handle` → [`KernelOut`].
//! SHM path: register → [`SharedMem::sync_in`] → map_into → invoke → [`SharedMem::sync_out`].

pub const PAGE_SIZE: usize = 4096;
pub const PARAM_COUNT: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhysRegion {
    pub base: u64,
    pub len: usize,
}

/// TEE-local. `shm_pool` is the bounce pool on virt (cookie = offset). Dual-map is tz/rv later, not a virt BAR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootInfo {
    pub ram: PhysRegion,
    pub shm_pool: PhysRegion,
    pub cpu_count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TeePhys(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtAddr(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Uuid(pub [u8; 16]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Perms {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

impl Perms {
    pub const READ: Self = Self { read: true, write: false, exec: false };
    pub const WRITE: Self = Self { read: false, write: true, exec: false };
    pub const RW: Self = Self { read: true, write: true, exec: false };
    pub const RX: Self = Self { read: true, write: false, exec: true };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    In,
    Out,
    InOut,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Login {
    Public,
    User,
    Group,
    UserApplication,
    GroupApplication,
    TrustedApp { uuid: Uuid },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Param {
    None,
    Value { a: u32, b: u32, dir: Dir },
    /// `cookie` is a bounce-pool offset on virt, never a host PA or dual-map GPA.
    Memref {
        cookie: u64,
        offs: usize,
        size: usize,
        dir: Dir,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelCmd {
    Open {
        uuid: Uuid,
        login: Login,
        params: [Param; PARAM_COUNT],
        cancel_id: u32,
    },
    Invoke {
        session: u32,
        func: u32,
        params: [Param; PARAM_COUNT],
        cancel_id: u32,
    },
    Close { session: u32 },
    Cancel { cancel_id: u32 },
}

/// HAL-neutral RPC. Proto writes this into the same call cookie.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HalRpc {
    LoadTa { uuid: Uuid },
    GetTime,
    Fs { cmd: u32, params: [Param; PARAM_COUNT] },
    ShmAlloc { size: usize, align: usize },
    ShmFree { cookie: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelOut {
    Done {
        ret: u32,
        origin: u32,
        session: Option<u32>,
        params: [Param; PARAM_COUNT],
    },
    Rpc(HalRpc),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HalError {
    Unsupported,
    InvalidParam,
    NoMemory,
    BadAlignment,
    PermDenied,
    Busy,
    Fault,
    NotFound,
}

pub struct Unsupported;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntropyOrigin {
    Isolated,
    ReeHost,
}

pub trait Entropy {
    fn fill(&mut self, buf: &mut [u8]);
    fn origin(&self) -> EntropyOrigin;
}

/// Never copied to REE. `material().len() >= 32`.
pub trait Huk {
    fn material(&self) -> &[u8];
}

pub trait Monotonic {
    fn next(&mut self) -> Result<u64, HalError>;
}
impl Monotonic for Unsupported {
    fn next(&mut self) -> Result<u64, HalError> {
        Err(HalError::Unsupported)
    }
}

pub trait SecureTime {
    fn now_ns(&self) -> Result<u64, HalError>;
}
impl SecureTime for Unsupported {
    fn now_ns(&self) -> Result<u64, HalError> {
        Err(HalError::Unsupported)
    }
}

pub struct IrqId(pub u32);
pub trait Irq {
    fn inject(&mut self, irq: IrqId) -> Result<(), HalError>;
    fn eoi(&mut self, irq: IrqId);
}
impl Irq for Unsupported {
    fn inject(&mut self, _: IrqId) -> Result<(), HalError> {
        Err(HalError::Unsupported)
    }
    fn eoi(&mut self, _: IrqId) {}
}

/// SMCCC-shaped world-switch frame. r[0] is a0.
/// CallGate unit (recv/complete/rpc_yield). virt vsock arg is this frame (8 LE u64s).
/// Fast SMCCC stays in rustee-virt.ko. tz-aarch64: SMC x0-x7 later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallFrame {
    pub r: [u64; 8],
}

impl CallFrame {
    /// Bounce-pool offset. SMCCC CALL_WITH_ARG: a1 = high 32, a2 = low 32.
    pub fn cookie_a1a2(self) -> u64 {
        ((self.r[1] & 0xffff_ffff) << 32) | (self.r[2] & 0xffff_ffff)
    }

    pub fn set_cookie_a1a2(&mut self, cookie: u64) {
        self.r[1] = cookie >> 32;
        self.r[2] = cookie & 0xffff_ffff;
    }
}

/// One outstanding yielding call on v0. `recv` while busy is [`HalError::Busy`].
pub trait CallGate {
    fn recv(&mut self) -> Result<CallFrame, HalError>;
    fn complete(&mut self, out: CallFrame) -> Result<(), HalError>;
    fn rpc_yield(&mut self, out: CallFrame) -> Result<CallFrame, HalError>;
}

pub trait AddressSpace {
    fn map_image(&mut self, va: VirtAddr, src: &[u8], perms: Perms) -> Result<(), HalError>;
    fn map_shm(&mut self, shm: &impl SharedMem, perms: Perms) -> Result<VirtAddr, HalError>;
    fn unmap(&mut self, va: VirtAddr);
    fn drop_all(&mut self);
}

pub use AddressSpace as TaAddressSpace;

pub trait SharedMem {
    fn cookie(&self) -> u64;
    fn len(&self) -> usize;
    fn perms(&self) -> Perms;
    /// REE → TEE. Bounce copy, cache invalidate, or no-op if coherent dual-map.
    fn sync_in(&mut self) -> Result<(), HalError>;
    /// TEE → REE. Bounce copy, cache clean, or no-op if coherent dual-map.
    fn sync_out(&mut self) -> Result<(), HalError>;
    /// Map into a TA AS. `perms.exec` is [`HalError::PermDenied`].
    fn map_into(&self, aspace: &mut impl AddressSpace, perms: Perms) -> Result<VirtAddr, HalError>;
}

pub trait Hal {
    type CallGate: CallGate;
    type AddressSpace: AddressSpace;
    type SharedMem: SharedMem;
    type Entropy: Entropy;
    type Huk: Huk;
    type Monotonic: Monotonic;
    type SecureTime: SecureTime;
    type Irq: Irq;

    fn call_gate(&mut self) -> &mut Self::CallGate;
    fn entropy(&mut self) -> &mut Self::Entropy;
    fn huk(&self) -> &Self::Huk;
    fn monotonic(&mut self) -> Option<&mut Self::Monotonic>;
    fn secure_time(&self) -> Option<&Self::SecureTime>;
    fn irq(&mut self) -> Option<&mut Self::Irq>;
    fn init(info: BootInfo) -> Result<Self, HalError> where Self: Sized;
    fn new_address_space(&mut self) -> Self::AddressSpace;
    fn lookup_shm(&self, cookie: u64) -> Option<&Self::SharedMem>;
    fn lookup_shm_mut(&mut self, cookie: u64) -> Option<&mut Self::SharedMem>;
}
