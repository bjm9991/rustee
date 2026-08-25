//! `.rustee.ta_head` 40-byte LE. Named GP fields, not an OP-TEE flags bitfield.

use crate::kernel_abi::Uuid;

pub const RTAH_MAGIC: u32 = 0x4841_5452;
pub const RTAH_ABI: u16 = 0;
pub const RTAH_SIZE: u16 = 40;
pub const SECTION_NAME: &str = ".rustee.ta_head";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaProperties {
    pub uuid: Uuid,
    pub stack_size: u32,
    pub data_size: u32,
    pub single_instance: bool,
    pub multi_session: bool,
    pub instance_keep_alive: bool,
    pub endian: u8,
    pub ta_version: u32,
}

const fn store_u16(b: &mut [u8; 40], off: usize, v: u16) {
    let x = v.to_le_bytes();
    b[off] = x[0];
    b[off + 1] = x[1];
}

const fn store_u32(b: &mut [u8; 40], off: usize, v: u32) {
    let x = v.to_le_bytes();
    b[off] = x[0];
    b[off + 1] = x[1];
    b[off + 2] = x[2];
    b[off + 3] = x[3];
}

pub const fn encode_ta_head(p: &TaProperties) -> [u8; 40] {
    let mut b = [0u8; 40];
    store_u32(&mut b, 0, RTAH_MAGIC);
    store_u16(&mut b, 4, RTAH_ABI);
    store_u16(&mut b, 6, RTAH_SIZE);
    let mut i = 0;
    while i < 16 {
        b[8 + i] = p.uuid.0[i];
        i += 1;
    }
    store_u32(&mut b, 24, p.stack_size);
    store_u32(&mut b, 28, p.data_size);
    b[32] = p.single_instance as u8;
    b[33] = p.multi_session as u8;
    b[34] = p.instance_keep_alive as u8;
    b[35] = p.endian;
    store_u32(&mut b, 36, p.ta_version);
    b
}

pub fn parse_ta_head(bytes: &[u8]) -> Option<TaProperties> {
    if bytes.len() < 40 {
        return None;
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let abi = u16::from_le_bytes(bytes[4..6].try_into().ok()?);
    let size = u16::from_le_bytes(bytes[6..8].try_into().ok()?);
    if magic != RTAH_MAGIC || abi != RTAH_ABI || size != RTAH_SIZE {
        return None;
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&bytes[8..24]);
    Some(TaProperties {
        uuid: Uuid(uuid),
        stack_size: u32::from_le_bytes(bytes[24..28].try_into().ok()?),
        data_size: u32::from_le_bytes(bytes[28..32].try_into().ok()?),
        single_instance: bytes[32] != 0,
        multi_session: bytes[33] != 0,
        instance_keep_alive: bytes[34] != 0,
        endian: bytes[35],
        ta_version: u32::from_le_bytes(bytes[36..40].try_into().ok()?),
    })
}

/// Optional trailer: desc_len, ver_str_len, UTF-8. Zero lengths → GP defaults.
pub fn parse_trailer(bytes: &[u8]) -> (Option<&str>, Option<&str>) {
    if bytes.len() < 40 + 4 {
        return (None, None);
    }
    let desc_len = u16::from_le_bytes(bytes[40..42].try_into().unwrap()) as usize;
    let ver_len = u16::from_le_bytes(bytes[42..44].try_into().unwrap()) as usize;
    let mut off = 44;
    let desc = if desc_len == 0 {
        None
    } else {
        let s = bytes
            .get(off..off + desc_len)
            .and_then(|b| core::str::from_utf8(b).ok());
        off += desc_len;
        s
    };
    let ver = if ver_len == 0 {
        None
    } else {
        bytes
            .get(off..off + ver_len)
            .and_then(|b| core::str::from_utf8(b).ok())
    };
    (desc, ver)
}
