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
