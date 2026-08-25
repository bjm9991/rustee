//! Property sets gpd.ta.*, gpd.client.*, gpd.tee.*. Honest values only.

use crate::header::TaProperties;
use crate::kernel_abi::Uuid;
use crate::param::Identity;
use crate::{
    TEE_ERROR_ITEM_NOT_FOUND, TEE_ERROR_SHORT_BUFFER, TEE_SUCCESS, TeeResult,
};

pub const PROPSET_TEE: usize = 0xFFFFFFFD;
pub const PROPSET_CLIENT: usize = 0xFFFFFFFE;
pub const PROPSET_TA: usize = 0xFFFFFFFF;

pub const INTERNAL_CORE_VERSION: u32 = 0x0103_0100;
pub const MAX_BIGINT_BITS: u32 = 4096;
pub const PROT_LEVEL_NONE: u32 = 0;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Str,
    Bool,
    U32,
    U64,
    Uuid,
    Identity,
}

pub struct Prop {
    pub set: usize,
    pub name: &'static str,
    pub kind: Kind,
}

pub const PROPS: &[Prop] = &[
    Prop { set: PROPSET_TA, name: "gpd.ta.appID", kind: Kind::Uuid },
    Prop { set: PROPSET_TA, name: "gpd.ta.singleInstance", kind: Kind::Bool },
    Prop { set: PROPSET_TA, name: "gpd.ta.multiSession", kind: Kind::Bool },
    Prop { set: PROPSET_TA, name: "gpd.ta.instanceKeepAlive", kind: Kind::Bool },
    Prop { set: PROPSET_TA, name: "gpd.ta.dataSize", kind: Kind::U32 },
    Prop { set: PROPSET_TA, name: "gpd.ta.stackSize", kind: Kind::U32 },
    Prop { set: PROPSET_TA, name: "gpd.ta.version", kind: Kind::Str },
    Prop { set: PROPSET_TA, name: "gpd.ta.description", kind: Kind::Str },
    Prop { set: PROPSET_TA, name: "gpd.ta.endian", kind: Kind::U32 },
    Prop {
        set: PROPSET_TA,
        name: "gpd.ta.doesNotCloseHandleOnCorruptObject",
        kind: Kind::Bool,
    },
    Prop { set: PROPSET_CLIENT, name: "gpd.client.identity", kind: Kind::Identity },
    Prop { set: PROPSET_CLIENT, name: "gpd.client.endian", kind: Kind::U32 },
    Prop { set: PROPSET_TEE, name: "gpd.tee.apiversion", kind: Kind::Str },
    Prop { set: PROPSET_TEE, name: "gpd.tee.internalCore.version", kind: Kind::U32 },
    Prop { set: PROPSET_TEE, name: "gpd.tee.description", kind: Kind::Str },
    Prop { set: PROPSET_TEE, name: "gpd.tee.deviceID", kind: Kind::Uuid },
    Prop {
        set: PROPSET_TEE,
        name: "gpd.tee.systemTime.protectionLevel",
        kind: Kind::U32,
    },
    Prop {
        set: PROPSET_TEE,
        name: "gpd.tee.TAPersistentTime.protectionLevel",
        kind: Kind::U32,
    },
    Prop { set: PROPSET_TEE, name: "gpd.tee.arith.maxBigIntSize", kind: Kind::U32 },
    Prop {
        set: PROPSET_TEE,
        name: "gpd.tee.trustedStorage.antiRollback.protectionLevel",
        kind: Kind::U32,
    },
    Prop { set: PROPSET_TEE, name: "gpd.tee.cryptography.ecc", kind: Kind::Bool },
    Prop { set: PROPSET_TEE, name: "gpd.tee.cryptography.nist", kind: Kind::Bool },
    Prop { set: PROPSET_TEE, name: "gpd.tee.cryptography.bsi-r", kind: Kind::Bool },
    Prop { set: PROPSET_TEE, name: "gpd.tee.cryptography.bsi-t", kind: Kind::Bool },
    Prop { set: PROPSET_TEE, name: "gpd.tee.cryptography.ietf", kind: Kind::Bool },
    Prop { set: PROPSET_TEE, name: "gpd.tee.cryptography.rsa", kind: Kind::Bool },
    Prop {
        set: PROPSET_TEE,
        name: "gpd.tee.trustedos.implementation.version",
        kind: Kind::Str,
    },
    Prop {
        set: PROPSET_TEE,
        name: "gpd.tee.trustedos.implementation.description",
        kind: Kind::Str,
    },
    Prop {
        set: PROPSET_TEE,
        name: "gpd.tee.firmware.implementation.version",
        kind: Kind::Str,
    },
    Prop {
        set: PROPSET_TEE,
        name: "gpd.tee.firmware.implementation.description",
        kind: Kind::Str,
    },
];

#[derive(Clone, Copy)]
pub struct PropCtx {
    pub ta: TaProperties,
    pub ta_version: &'static str,
    pub ta_description: &'static str,
    pub client: Identity,
}

impl PropCtx {
    pub const fn new() -> Self {
        Self {
            ta: TaProperties {
                uuid: Uuid([0; 16]),
                stack_size: 4096,
                data_size: 4096,
                single_instance: true,
                multi_session: false,
                instance_keep_alive: false,
                endian: 0,
                ta_version: 1,
            },
            ta_version: "0.1.0",
            ta_description: "RUSTEE TA",
            client: Identity {
                login: 0,
                uuid: Uuid([0; 16]),
            },
        }
    }
}

impl Default for PropCtx {
    fn default() -> Self {
        Self::new()
    }
}

pub fn find(set: usize, name: &str) -> Option<&'static Prop> {
    PROPS.iter().find(|p| p.set == set && p.name == name)
}

pub fn is_propset(handle: usize) -> bool {
    handle == PROPSET_TA || handle == PROPSET_CLIENT || handle == PROPSET_TEE
}

pub fn get_u32(ctx: &PropCtx, set: usize, name: &str) -> Result<u32, TeeResult> {
    let p = find(set, name).ok_or(TEE_ERROR_ITEM_NOT_FOUND)?;
    match (p.kind, name) {
        (Kind::U32, "gpd.ta.dataSize") => Ok(ctx.ta.data_size),
        (Kind::U32, "gpd.ta.stackSize") => Ok(ctx.ta.stack_size),
        (Kind::U32, "gpd.ta.endian") => Ok(ctx.ta.endian as u32),
        (Kind::U32, "gpd.client.endian") => Ok(0),
        (Kind::U32, "gpd.tee.internalCore.version") => Ok(INTERNAL_CORE_VERSION),
        (Kind::U32, "gpd.tee.systemTime.protectionLevel") => Ok(PROT_LEVEL_NONE),
        (Kind::U32, "gpd.tee.TAPersistentTime.protectionLevel") => Ok(PROT_LEVEL_NONE),
        (Kind::U32, "gpd.tee.arith.maxBigIntSize") => Ok(MAX_BIGINT_BITS),
        (Kind::U32, "gpd.tee.trustedStorage.antiRollback.protectionLevel") => Ok(PROT_LEVEL_NONE),
        (Kind::Bool, _) => Ok(get_bool(ctx, set, name)? as u32),
        _ => Err(TEE_ERROR_ITEM_NOT_FOUND),
    }
}

pub fn get_bool(ctx: &PropCtx, set: usize, name: &str) -> Result<bool, TeeResult> {
    match name {
        "gpd.ta.singleInstance" if set == PROPSET_TA => Ok(ctx.ta.single_instance),
        "gpd.ta.multiSession" if set == PROPSET_TA => Ok(ctx.ta.multi_session),
        "gpd.ta.instanceKeepAlive" if set == PROPSET_TA => Ok(ctx.ta.instance_keep_alive),
        "gpd.ta.doesNotCloseHandleOnCorruptObject" if set == PROPSET_TA => Ok(false),
        "gpd.tee.cryptography.ecc"
        | "gpd.tee.cryptography.nist"
        | "gpd.tee.cryptography.bsi-r"
        | "gpd.tee.cryptography.bsi-t"
        | "gpd.tee.cryptography.ietf"
        | "gpd.tee.cryptography.rsa"
            if set == PROPSET_TEE =>
        {
            Ok(false)
        }
        _ => Err(TEE_ERROR_ITEM_NOT_FOUND),
    }
}

pub fn get_str<'a>(ctx: &'a PropCtx, set: usize, name: &str) -> Result<&'a str, TeeResult> {
    match name {
        "gpd.ta.version" if set == PROPSET_TA => Ok(ctx.ta_version),
        "gpd.ta.description" if set == PROPSET_TA => Ok(ctx.ta_description),
        "gpd.tee.apiversion" if set == PROPSET_TEE => Ok("1.3.1"),
        "gpd.tee.description" if set == PROPSET_TEE => {
            Ok("RUSTEE: GPD_SPE_010 v1.3.1 identifiers; Internal Core not complete")
        }
        "gpd.tee.trustedos.implementation.version" if set == PROPSET_TEE => Ok("0.1.0"),
        "gpd.tee.trustedos.implementation.description" if set == PROPSET_TEE => Ok("RUSTEE"),
        "gpd.tee.firmware.implementation.version" if set == PROPSET_TEE => Ok("0.1.0"),
        "gpd.tee.firmware.implementation.description" if set == PROPSET_TEE => Ok("RUSTEE"),
        _ => Err(TEE_ERROR_ITEM_NOT_FOUND),
    }
}

pub fn get_u64(ctx: &PropCtx, set: usize, name: &str) -> Result<u64, TeeResult> {
    if let Ok(v) = get_u32(ctx, set, name) {
        return Ok(v as u64);
    }
    Err(TEE_ERROR_ITEM_NOT_FOUND)
}

pub fn get_uuid(ctx: &PropCtx, set: usize, name: &str) -> Result<Uuid, TeeResult> {
    match name {
        "gpd.ta.appID" if set == PROPSET_TA => Ok(ctx.ta.uuid),
        "gpd.tee.deviceID" if set == PROPSET_TEE => Ok(Uuid([0; 16])),
        _ => Err(TEE_ERROR_ITEM_NOT_FOUND),
    }
}

pub fn get_identity(ctx: &PropCtx, set: usize, name: &str) -> Result<Identity, TeeResult> {
    match name {
        "gpd.client.identity" if set == PROPSET_CLIENT => Ok(ctx.client),
        _ => Err(TEE_ERROR_ITEM_NOT_FOUND),
    }
}

pub fn copy_str(s: &str, out: &mut [u8]) -> Result<usize, TeeResult> {
    let need = s.len() + 1;
    if out.len() < need {
        return Err(TEE_ERROR_SHORT_BUFFER);
    }
    out[..s.len()].copy_from_slice(s.as_bytes());
    out[s.len()] = 0;
    Ok(need)
}

pub fn names_for(set: usize) -> impl Iterator<Item = &'static str> {
    PROPS.iter().filter(move |p| p.set == set).map(|p| p.name)
}

pub fn name_at(set: usize, idx: usize) -> Option<&'static str> {
    names_for(set).nth(idx)
}

pub fn name_count(set: usize) -> usize {
    names_for(set).count()
}

pub fn binary_of(ctx: &PropCtx, set: usize, name: &str, out: &mut [u8]) -> Result<usize, TeeResult> {
    if let Ok(u) = get_uuid(ctx, set, name) {
        if out.len() < 16 {
            return Err(TEE_ERROR_SHORT_BUFFER);
        }
        out[..16].copy_from_slice(&u.0);
        return Ok(16);
    }
    if let Ok(id) = get_identity(ctx, set, name) {
        if out.len() < 20 {
            return Err(TEE_ERROR_SHORT_BUFFER);
        }
        out[..4].copy_from_slice(&id.login.to_le_bytes());
        out[4..20].copy_from_slice(&id.uuid.0);
        return Ok(20);
    }
    if let Ok(v) = get_u32(ctx, set, name) {
        if find(set, name).map(|p| p.kind) == Some(Kind::Bool) {
            if out.is_empty() {
                return Err(TEE_ERROR_SHORT_BUFFER);
            }
            out[0] = v as u8;
            return Ok(1);
        }
        if out.len() < 4 {
            return Err(TEE_ERROR_SHORT_BUFFER);
        }
        out[..4].copy_from_slice(&v.to_le_bytes());
        return Ok(4);
    }
    if let Ok(s) = get_str(ctx, set, name) {
        if out.len() < s.len() {
            return Err(TEE_ERROR_SHORT_BUFFER);
        }
        out[..s.len()].copy_from_slice(s.as_bytes());
        return Ok(s.len());
    }
    Err(TEE_ERROR_ITEM_NOT_FOUND)
}

pub const fn success() -> TeeResult {
    TEE_SUCCESS
}
