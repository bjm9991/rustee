//! Kernel syscall ABI. Proto and utee marshal to these types. Never `optee_msg_arg`.

use core::fmt;

pub const PARAM_COUNT: usize = 4;
pub const TEE_TIMEOUT_INFINITE: u32 = 0xFFFF_FFFF;

pub const TEE_SUCCESS: u32 = 0x0000_0000;
pub const TEE_ERROR_CANCEL: u32 = 0xFFFF_0002;
pub const TEE_ERROR_BAD_PARAMETERS: u32 = 0xFFFF_0006;
pub const TEE_ERROR_ITEM_NOT_FOUND: u32 = 0xFFFF_0008;
pub const TEE_ERROR_NOT_SUPPORTED: u32 = 0xFFFF_000A;
pub const TEE_ERROR_OUT_OF_MEMORY: u32 = 0xFFFF_000C;
pub const TEE_ERROR_BUSY: u32 = 0xFFFF_000D;
pub const TEE_ERROR_SECURITY: u32 = 0xFFFF_000F;
pub const TEE_ERROR_TARGET_DEAD: u32 = 0xFFFF_3024;

pub const TEE_ORIGIN_TEE: u32 = 0x0000_0003;
pub const TEE_ORIGIN_TRUSTED_APP: u32 = 0x0000_0004;

pub const TEE_LOGIN_PUBLIC: u32 = 0x0000_0000;
pub const TEE_LOGIN_USER: u32 = 0x0000_0001;
pub const TEE_LOGIN_GROUP: u32 = 0x0000_0002;
pub const TEE_LOGIN_APPLICATION: u32 = 0x0000_0004;
pub const TEE_LOGIN_USER_APPLICATION: u32 = 0x0000_0005;
pub const TEE_LOGIN_GROUP_APPLICATION: u32 = 0x0000_0006;
pub const TEE_LOGIN_TRUSTED_APP: u32 = 0xF000_0000;

pub const PERM_READ: u32 = 1;
pub const PERM_WRITE: u32 = 2;
pub const PERM_EXEC: u32 = 4;
pub const PERM_SHM: u32 = 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Uuid(pub [u8; 16]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InstanceId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Tee,
    TrustedApp,
}

impl Origin {
    pub fn as_gp(self) -> u32 {
        match self {
            Origin::Tee => TEE_ORIGIN_TEE,
            Origin::TrustedApp => TEE_ORIGIN_TRUSTED_APP,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TeeResult {
    pub code: u32,
    pub origin: Origin,
}

impl TeeResult {
    pub const fn ok() -> Self {
        Self {
            code: TEE_SUCCESS,
            origin: Origin::Tee,
        }
    }
    pub const fn tee(code: u32) -> Self {
        Self {
            code,
            origin: Origin::Tee,
        }
    }
    pub const fn ta(code: u32) -> Self {
        Self {
            code,
            origin: Origin::TrustedApp,
        }
    }
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
    Group { gid: u32 },
    Application,
    UserApplication,
    GroupApplication { gid: u32 },
    TrustedApp { uuid: Uuid },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemrefSrc {
    /// CA path. Cookie is a bounce-pool offset, never a PA.
    Ree { cookie: u64, offs: usize },
    /// TA-to-TA: buffer VA in the caller aspace. Skips REE bounce.
    Ta { va: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Param {
    None,
    Value { a: u32, b: u32, dir: Dir },
    Memref {
        src: MemrefSrc,
        size: usize,
        dir: Dir,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HalRpc {
    LoadTa { uuid: Uuid },
    GetTime,
    Fs,
    ShmAlloc,
    ShmFree,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RpcResponse {
    LoadTa { bytes: alloc::vec::Vec<u8> },
    Time { seconds: u32, millis: u32 },
    Fs { result: u32 },
    Shm { cookie: u64 },
    Error { code: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KernelCmd {
    OpenSession {
        uuid: Uuid,
        login: Login,
        params: [Param; PARAM_COUNT],
        cancel_id: u32,
        timeout_ms: u32,
    },
    Invoke {
        session: SessionId,
        cmd_id: u32,
        params: [Param; PARAM_COUNT],
        cancel_id: u32,
        timeout_ms: u32,
    },
    CloseSession {
        session: SessionId,
    },
    Cancel {
        cancel_id: u32,
    },
    RpcComplete {
        resp: RpcResponse,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KernelOut {
    Done {
        result: TeeResult,
        session: Option<SessionId>,
        params: [Param; PARAM_COUNT],
    },
    Rpc(HalRpc),
}

impl KernelOut {
    pub fn done_err(code: u32) -> Self {
        Self::Done {
            result: TeeResult::tee(code),
            session: None,
            params: [Param::None; PARAM_COUNT],
        }
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if i == 4 || i == 6 || i == 8 || i == 10 {
                write!(f, "-")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

pub const TEE_ERROR_SHORT_BUFFER: u32 = 0xFFFF_0010;
pub const TEE_PARAM_TYPE_NONE: u32 = 0;
pub const TEE_PARAM_TYPE_VALUE_INPUT: u32 = 1;
pub const TEE_PARAM_TYPE_VALUE_OUTPUT: u32 = 2;
pub const TEE_PARAM_TYPE_VALUE_INOUT: u32 = 3;
pub const TEE_PARAM_TYPE_MEMREF_INPUT: u32 = 5;
pub const TEE_PARAM_TYPE_MEMREF_OUTPUT: u32 = 6;
pub const TEE_PARAM_TYPE_MEMREF_INOUT: u32 = 7;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemrefRaw {
    pub buffer: *mut u8,
    pub size: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ValueRaw {
    pub a: u32,
    pub b: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union ParamRaw {
    pub memref: MemrefRaw,
    pub value: ValueRaw,
}

impl ParamRaw {
    pub const fn none() -> Self {
        Self {
            value: ValueRaw { a: 0, b: 0 },
        }
    }
}

/// GP TA entry points. Signatures match rustee-utee / GPD_SPE_010.
#[derive(Clone, Copy)]
pub struct TaEntryPoints {
    pub create: unsafe extern "C" fn() -> u32,
    pub destroy: unsafe extern "C" fn(),
    pub open_session: unsafe extern "C" fn(u32, *mut ParamRaw, *mut usize) -> u32,
    pub close_session: unsafe extern "C" fn(usize),
    pub invoke: unsafe extern "C" fn(usize, u32, u32, *mut ParamRaw) -> u32,
}

pub fn param_types_of(params: &[Param; PARAM_COUNT]) -> u32 {
    let mut t = 0u32;
    for (i, p) in params.iter().enumerate() {
        let n = match p {
            Param::None => 0,
            Param::Value { dir: Dir::In, .. } => TEE_PARAM_TYPE_VALUE_INPUT,
            Param::Value { dir: Dir::Out, .. } => TEE_PARAM_TYPE_VALUE_OUTPUT,
            Param::Value { dir: Dir::InOut, .. } => TEE_PARAM_TYPE_VALUE_INOUT,
            Param::Memref { dir: Dir::In, .. } => TEE_PARAM_TYPE_MEMREF_INPUT,
            Param::Memref { dir: Dir::Out, .. } => TEE_PARAM_TYPE_MEMREF_OUTPUT,
            Param::Memref { dir: Dir::InOut, .. } => TEE_PARAM_TYPE_MEMREF_INOUT,
        };
        t |= n << (4 * i);
    }
    t
}

pub fn params_to_raw(params: &[Param; PARAM_COUNT]) -> [ParamRaw; PARAM_COUNT] {
    let mut raw = [ParamRaw::none(); PARAM_COUNT];
    for (i, p) in params.iter().enumerate() {
        raw[i] = match *p {
            Param::None => ParamRaw::none(),
            Param::Value { a, b, .. } => ParamRaw {
                value: ValueRaw { a, b },
            },
            Param::Memref { src, size, .. } => {
                let va = match src {
                    MemrefSrc::Ta { va } => va,
                    MemrefSrc::Ree { .. } => 0,
                };
                ParamRaw {
                    memref: MemrefRaw {
                        buffer: va as *mut u8,
                        size,
                    },
                }
            }
        };
    }
    raw
}

pub fn params_from_raw(params: &mut [Param; PARAM_COUNT], raw: &[ParamRaw; PARAM_COUNT]) {
    for i in 0..PARAM_COUNT {
        match &mut params[i] {
            Param::Value {
                a,
                b,
                dir: Dir::Out | Dir::InOut,
            } => unsafe {
                *a = raw[i].value.a;
                *b = raw[i].value.b;
            },
            Param::Memref {
                size,
                dir: Dir::Out | Dir::InOut,
                ..
            } => unsafe {
                *size = raw[i].memref.size;
            },
            _ => {}
        }
    }
}
