//! Syscall ABI shared with rustee-os (KernelCmd / Param). Not MSG.
//! Duplicated here so TAs do not link rustee-os.

pub const PARAM_COUNT: usize = 4;
pub const TEE_TIMEOUT_INFINITE: u32 = 0xFFFF_FFFF;

pub const TEE_LOGIN_PUBLIC: u32 = 0x0000_0000;
pub const TEE_LOGIN_USER: u32 = 0x0000_0001;
pub const TEE_LOGIN_GROUP: u32 = 0x0000_0002;
pub const TEE_LOGIN_APPLICATION: u32 = 0x0000_0004;
pub const TEE_LOGIN_USER_APPLICATION: u32 = 0x0000_0005;
pub const TEE_LOGIN_GROUP_APPLICATION: u32 = 0x0000_0006;
pub const TEE_LOGIN_TRUSTED_APP: u32 = 0xF000_0000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Uuid(pub [u8; 16]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(pub u32);

impl SessionId {
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Tee,
    TrustedApp,
}

impl Origin {
    pub const fn as_gp(self) -> u32 {
        match self {
            Origin::Tee => crate::TEE_ORIGIN_TEE,
            Origin::TrustedApp => crate::TEE_ORIGIN_TRUSTED_APP,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TeeResult {
    pub code: u32,
    pub origin: Origin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    In,
    Out,
    InOut,
}

impl Dir {
    pub const fn is_out(self) -> bool {
        matches!(self, Dir::Out | Dir::InOut)
    }
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

impl Login {
    pub const fn as_gp(&self) -> u32 {
        match self {
            Login::Public => TEE_LOGIN_PUBLIC,
            Login::User => TEE_LOGIN_USER,
            Login::Group { .. } => TEE_LOGIN_GROUP,
            Login::Application => TEE_LOGIN_APPLICATION,
            Login::UserApplication => TEE_LOGIN_USER_APPLICATION,
            Login::GroupApplication { .. } => TEE_LOGIN_GROUP_APPLICATION,
            Login::TrustedApp { .. } => TEE_LOGIN_TRUSTED_APP,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemrefSrc {
    Ree { cookie: u64, offs: usize },
    Ta { va: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Param {
    None,
    Value { a: u32, b: u32, dir: Dir },
    Memref { src: MemrefSrc, size: usize, dir: Dir },
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
    CloseSession { session: SessionId },
    Cancel { cancel_id: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KernelOut {
    Done {
        result: TeeResult,
        session: Option<SessionId>,
        params: [Param; PARAM_COUNT],
    },
}

pub trait TeeSyscall {
    fn handle(&mut self, cmd: KernelCmd) -> KernelOut;
}

pub const fn param_types(t0: u32, t1: u32, t2: u32, t3: u32) -> u32 {
    t0 | (t1 << 4) | (t2 << 8) | (t3 << 12)
}

pub const fn param_type_get(param_types: u32, i: usize) -> u32 {
    (param_types >> (i * 4)) & 0xF
}

pub fn nibble_to_dir(n: u32) -> Option<Dir> {
    match n {
        1 | 5 => Some(Dir::In),
        2 | 6 => Some(Dir::Out),
        3 | 7 => Some(Dir::InOut),
        _ => None,
    }
}

pub fn param_nibble(p: &Param) -> u32 {
    match p {
        Param::None => 0,
        Param::Value { dir: Dir::In, .. } => 1,
        Param::Value { dir: Dir::Out, .. } => 2,
        Param::Value { dir: Dir::InOut, .. } => 3,
        Param::Memref { dir: Dir::In, .. } => 5,
        Param::Memref { dir: Dir::Out, .. } => 6,
        Param::Memref { dir: Dir::InOut, .. } => 7,
    }
}

pub fn param_from_gp(
    param_types: u32,
    i: usize,
    a: u32,
    b: u32,
    buf: usize,
    size: usize,
) -> Result<Param, u32> {
    let t = param_type_get(param_types, i);
    match t {
        0 => Ok(Param::None),
        1 => Ok(Param::Value {
            a,
            b,
            dir: Dir::In,
        }),
        2 => Ok(Param::Value {
            a,
            b,
            dir: Dir::Out,
        }),
        3 => Ok(Param::Value {
            a,
            b,
            dir: Dir::InOut,
        }),
        5 => Ok(Param::Memref {
            src: MemrefSrc::Ta { va: buf },
            size,
            dir: Dir::In,
        }),
        6 => Ok(Param::Memref {
            src: MemrefSrc::Ta { va: buf },
            size,
            dir: Dir::Out,
        }),
        7 => Ok(Param::Memref {
            src: MemrefSrc::Ta { va: buf },
            size,
            dir: Dir::InOut,
        }),
        _ => Err(crate::TEE_ERROR_BAD_PARAMETERS),
    }
}
