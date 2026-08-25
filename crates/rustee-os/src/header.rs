//! `.rustee.ta_head` (kernel ABI) and RTSG signed envelope (load format).

use crate::abi::{Uuid, TEE_ERROR_BAD_PARAMETERS, TEE_ERROR_SECURITY};

pub const RTAH_MAGIC: u32 = 0x4841_5452; // 'RTAH' LE
pub const RTAH_ABI: u16 = 0;
pub const RTAH_SIZE: u16 = 40;
pub const RTSG_MAGIC: u32 = 0x4753_5452; // 'RTSG' LE
pub const RTSG_ABI: u16 = 0;
pub const SECTION_NAME: &str = ".rustee.ta_head";

/// Compiled-in v0 development public key. CryptoProvider verifies; rustee-os
/// does not implement RSA. Placeholder 32-byte id until rustee-crypto ships the real key.
pub static V0_DEV_PUBKEY: &[u8] = b"RUSTEE-V0-DEV-PUBKEY-PLACEHOLDER!";

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

impl TaProperties {
    pub fn validate(&self) -> Result<(), u32> {
        if self.endian != 0 {
            return Err(TEE_ERROR_BAD_PARAMETERS);
        }
        if self.stack_size == 0 || self.data_size == 0 {
            return Err(TEE_ERROR_BAD_PARAMETERS);
        }
        if !self.single_instance && (self.multi_session || self.instance_keep_alive) {
            return Err(TEE_ERROR_BAD_PARAMETERS);
        }
        Ok(())
    }
}

pub fn parse_ta_head(bytes: &[u8]) -> Result<TaProperties, u32> {
    if bytes.len() < RTAH_SIZE as usize {
        return Err(TEE_ERROR_BAD_PARAMETERS);
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let abi = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    let size = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
    if magic != RTAH_MAGIC || abi != RTAH_ABI || size != RTAH_SIZE {
        return Err(TEE_ERROR_BAD_PARAMETERS);
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&bytes[8..24]);
    let props = TaProperties {
        uuid: Uuid(uuid),
        stack_size: u32::from_le_bytes(bytes[24..28].try_into().unwrap()),
        data_size: u32::from_le_bytes(bytes[28..32].try_into().unwrap()),
        single_instance: bytes[32] != 0,
        multi_session: bytes[33] != 0,
        instance_keep_alive: bytes[34] != 0,
        endian: bytes[35],
        ta_version: u32::from_le_bytes(bytes[36..40].try_into().unwrap()),
    };
    props.validate()?;
    Ok(props)
}

pub fn encode_ta_head(p: &TaProperties) -> [u8; 40] {
    let mut b = [0u8; 40];
    b[0..4].copy_from_slice(&RTAH_MAGIC.to_le_bytes());
    b[4..6].copy_from_slice(&RTAH_ABI.to_le_bytes());
    b[6..8].copy_from_slice(&RTAH_SIZE.to_le_bytes());
    b[8..24].copy_from_slice(&p.uuid.0);
    b[24..28].copy_from_slice(&p.stack_size.to_le_bytes());
    b[28..32].copy_from_slice(&p.data_size.to_le_bytes());
    b[32] = p.single_instance as u8;
    b[33] = p.multi_session as u8;
    b[34] = p.instance_keep_alive as u8;
    b[35] = p.endian;
    b[36..40].copy_from_slice(&p.ta_version.to_le_bytes());
    b
}

/// RTSG envelope: magic, abi, img_type, uuid, ta_version, img_size, hash_size, sig_size,
/// then hash, sig, ELF.
#[derive(Clone, Debug)]
pub struct SignedImage<'a> {
    pub uuid: Uuid,
    pub ta_version: u32,
    pub hash: &'a [u8],
    pub sig: &'a [u8],
    pub elf: &'a [u8],
}

pub fn parse_rtsg(bytes: &[u8]) -> Result<SignedImage<'_>, u32> {
    if bytes.len() < 40 {
        return Err(TEE_ERROR_BAD_PARAMETERS);
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let abi = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    if magic != RTSG_MAGIC || abi != RTSG_ABI {
        return Err(TEE_ERROR_SECURITY);
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&bytes[8..24]);
    let ta_version = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
    let img_size = u32::from_le_bytes(bytes[28..32].try_into().unwrap()) as usize;
    let hash_size = u16::from_le_bytes(bytes[32..34].try_into().unwrap()) as usize;
    let sig_size = u16::from_le_bytes(bytes[34..36].try_into().unwrap()) as usize;
    let rest = 36;
    if bytes.len() < rest + hash_size + sig_size + img_size {
        return Err(TEE_ERROR_BAD_PARAMETERS);
    }
    let hash = &bytes[rest..rest + hash_size];
    let sig = &bytes[rest + hash_size..rest + hash_size + sig_size];
    let elf = &bytes[rest + hash_size + sig_size..rest + hash_size + sig_size + img_size];
    Ok(SignedImage {
        uuid: Uuid(uuid),
        ta_version,
        hash,
        sig,
        elf,
    })
}

/// Minimal ELF64 LE lookup of `.rustee.ta_head`. Early TAs may be a raw 40-byte header.
pub fn find_ta_head<'a>(image: &'a [u8]) -> Result<&'a [u8], u32> {
    if image.len() >= 40 && u32::from_le_bytes(image[0..4].try_into().unwrap()) == RTAH_MAGIC {
        return Ok(&image[..40]);
    }
    elf64_section(image, SECTION_NAME)
}

fn elf64_section<'a>(image: &'a [u8], name: &str) -> Result<&'a [u8], u32> {
    if image.len() < 64 || image[0..4] != [0x7f, b'E', b'L', b'F'] || image[4] != 2 || image[5] != 1
    {
        return Err(TEE_ERROR_BAD_PARAMETERS);
    }
    let shoff = u64::from_le_bytes(image[40..48].try_into().unwrap()) as usize;
    let shentsize = u16::from_le_bytes(image[58..60].try_into().unwrap()) as usize;
    let shnum = u16::from_le_bytes(image[60..62].try_into().unwrap()) as usize;
    let shstrndx = u16::from_le_bytes(image[62..64].try_into().unwrap()) as usize;
    if shentsize < 64 || shoff == 0 {
        return Err(TEE_ERROR_BAD_PARAMETERS);
    }
    let shstr = shoff + shstrndx * shentsize;
    if image.len() < shstr + 64 {
        return Err(TEE_ERROR_BAD_PARAMETERS);
    }
    let str_off = u64::from_le_bytes(image[shstr + 24..shstr + 32].try_into().unwrap()) as usize;
    let str_size = u64::from_le_bytes(image[shstr + 32..shstr + 40].try_into().unwrap()) as usize;
    let strtab = image.get(str_off..str_off.saturating_add(str_size)).ok_or(TEE_ERROR_BAD_PARAMETERS)?;
    for i in 0..shnum {
        let off = shoff + i * shentsize;
        if image.len() < off + 64 {
            return Err(TEE_ERROR_BAD_PARAMETERS);
        }
        let name_off = u32::from_le_bytes(image[off..off + 4].try_into().unwrap()) as usize;
        let sec_off = u64::from_le_bytes(image[off + 24..off + 32].try_into().unwrap()) as usize;
        let sec_size = u64::from_le_bytes(image[off + 32..off + 40].try_into().unwrap()) as usize;
        if section_name(strtab, name_off) == Some(name) {
            return image
                .get(sec_off..sec_off.saturating_add(sec_size))
                .ok_or(TEE_ERROR_BAD_PARAMETERS);
        }
    }
    Err(TEE_ERROR_BAD_PARAMETERS)
}

fn section_name(strtab: &[u8], off: usize) -> Option<&str> {
    let s = strtab.get(off..)?;
    let end = s.iter().position(|&b| b == 0)?;
    core::str::from_utf8(&s[..end]).ok()
}
