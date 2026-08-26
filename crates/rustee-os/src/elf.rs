//! ELF64 LE: PT_LOAD segments and GP TA_* symbols.

use crate::abi::TEE_ERROR_BAD_PARAMETERS;
use crate::header::{find_ta_head, parse_ta_head, SECTION_NAME, TaProperties};

pub const TA_CREATE: &str = "TA_CreateEntryPoint";
pub const TA_DESTROY: &str = "TA_DestroyEntryPoint";
pub const TA_OPEN: &str = "TA_OpenSessionEntryPoint";
pub const TA_CLOSE: &str = "TA_CloseSessionEntryPoint";
pub const TA_INVOKE: &str = "TA_InvokeCommandEntryPoint";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadSeg {
    pub va: u64,
    pub file_off: usize,
    pub file_size: usize,
    pub mem_size: usize,
    pub exec: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaSymbols {
    pub create: u64,
    pub destroy: u64,
    pub open_session: u64,
    pub close_session: u64,
    pub invoke: u64,
}

#[allow(dead_code)]
pub struct ElfImage<'a> {
    pub bytes: &'a [u8],
    pub props: TaProperties,
    pub segs: alloc::vec::Vec<LoadSeg>,
    pub symbols: Option<TaSymbols>,
}

pub fn parse_elf(bytes: &[u8]) -> Result<ElfImage<'_>, u32> {
    let head = find_ta_head(bytes)?;
    let props = parse_ta_head(head)?;
    if bytes.len() < 64 || bytes[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Ok(ElfImage {
            bytes,
            props,
            segs: alloc::vec::Vec::new(),
            symbols: None,
        });
    }
    let segs = pt_load(bytes)?;
    let symbols = ta_symbols(bytes).ok();
    Ok(ElfImage {
        bytes,
        props,
        segs,
        symbols,
    })
}

fn pt_load(bytes: &[u8]) -> Result<alloc::vec::Vec<LoadSeg>, u32> {
    let phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let phentsize = u16::from_le_bytes(bytes[54..56].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    let mut segs = alloc::vec::Vec::new();
    for i in 0..phnum {
        let o = phoff + i * phentsize;
        if bytes.len() < o + 56 {
            return Err(TEE_ERROR_BAD_PARAMETERS);
        }
        let p_type = u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
        if p_type != 1 {
            continue;
        }
        let flags = u32::from_le_bytes(bytes[o + 4..o + 8].try_into().unwrap());
        let off = u64::from_le_bytes(bytes[o + 8..o + 16].try_into().unwrap()) as usize;
        let va = u64::from_le_bytes(bytes[o + 16..o + 24].try_into().unwrap());
        let filesz = u64::from_le_bytes(bytes[o + 32..o + 40].try_into().unwrap()) as usize;
        let memsz = u64::from_le_bytes(bytes[o + 40..o + 48].try_into().unwrap()) as usize;
        segs.push(LoadSeg {
            va,
            file_off: off,
            file_size: filesz,
            mem_size: memsz,
            exec: flags & 1 != 0,
        });
    }
    Ok(segs)
}

fn ta_symbols(bytes: &[u8]) -> Result<TaSymbols, u32> {
    // Scan SHT_SYMTAB (2) and SHT_DYNSYM (11)
    let shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
    let shentsize = u16::from_le_bytes(bytes[58..60].try_into().unwrap()) as usize;
    let shnum = u16::from_le_bytes(bytes[60..62].try_into().unwrap()) as usize;
    let mut names = [
        (TA_CREATE, 0u64),
        (TA_DESTROY, 0u64),
        (TA_OPEN, 0u64),
        (TA_CLOSE, 0u64),
        (TA_INVOKE, 0u64),
    ];
    for i in 0..shnum {
        let o = shoff + i * shentsize;
        if bytes.len() < o + 64 {
            return Err(TEE_ERROR_BAD_PARAMETERS);
        }
        let sh_type = u32::from_le_bytes(bytes[o + 4..o + 8].try_into().unwrap());
        if sh_type != 2 && sh_type != 11 {
            continue;
        }
        let sh_link = u32::from_le_bytes(bytes[o + 40..o + 44].try_into().unwrap()) as usize;
        let sym_off = u64::from_le_bytes(bytes[o + 24..o + 32].try_into().unwrap()) as usize;
        let sym_size = u64::from_le_bytes(bytes[o + 32..o + 40].try_into().unwrap()) as usize;
        let ent = u64::from_le_bytes(bytes[o + 56..o + 64].try_into().unwrap()) as usize;
        if ent == 0 {
            continue;
        }
        let str_hdr = shoff + sh_link * shentsize;
        if bytes.len() < str_hdr + 40 {
            continue;
        }
        let str_off = u64::from_le_bytes(bytes[str_hdr + 24..str_hdr + 32].try_into().unwrap()) as usize;
        let str_size = u64::from_le_bytes(bytes[str_hdr + 32..str_hdr + 40].try_into().unwrap()) as usize;
        let strtab = bytes.get(str_off..str_off + str_size).ok_or(TEE_ERROR_BAD_PARAMETERS)?;
        let n = sym_size / ent;
        for s in 0..n {
            let so = sym_off + s * ent;
            if bytes.len() < so + 24 {
                break;
            }
            let name_off = u32::from_le_bytes(bytes[so..so + 4].try_into().unwrap()) as usize;
            let value = u64::from_le_bytes(bytes[so + 8..so + 16].try_into().unwrap());
            let name = str_name(strtab, name_off).unwrap_or("");
            for (want, slot) in names.iter_mut() {
                if name == *want {
                    *slot = value;
                }
            }
        }
    }
    if names.iter().any(|(_, v)| *v == 0) {
        return Err(TEE_ERROR_BAD_PARAMETERS);
    }
    Ok(TaSymbols {
        create: names[0].1,
        destroy: names[1].1,
        open_session: names[2].1,
        close_session: names[3].1,
        invoke: names[4].1,
    })
}

fn str_name(tab: &[u8], off: usize) -> Option<&str> {
    let s = tab.get(off..)?;
    let end = s.iter().position(|&b| b == 0)?;
    core::str::from_utf8(&s[..end]).ok()
}

#[allow(dead_code)]
pub fn _section_name() -> &'static str {
    SECTION_NAME
}

use crate::abi::TaEntryPoints;
use rustee_hal::{AddressSpace, HalError, Perms, VirtAddr};

/// Map PT_LOAD into the TA aspace. On aarch64, bind GP TA_* VAs as entry points.
pub fn map_elf<A: AddressSpace>(aspace: &mut A, bytes: &[u8]) -> Result<Option<TaEntryPoints>, u32> {
    let img = parse_elf(bytes)?;
    for seg in &img.segs {
        let end = seg.file_off.saturating_add(seg.file_size);
        let src = bytes.get(seg.file_off..end).ok_or(TEE_ERROR_BAD_PARAMETERS)?;
        let perms = if seg.exec { Perms::RX } else { Perms::RW };
        aspace
            .map_image(VirtAddr(seg.va), src, perms)
            .map_err(|_| TEE_ERROR_BAD_PARAMETERS)?;
    }
    Ok(bind_symbols(img.symbols))
}

fn bind_symbols(symbols: Option<TaSymbols>) -> Option<TaEntryPoints> {
    let s = symbols?;
    #[cfg(target_arch = "aarch64")]
    unsafe {
        return Some(TaEntryPoints {
            create: core::mem::transmute(s.create as usize),
            destroy: core::mem::transmute(s.destroy as usize),
            open_session: core::mem::transmute(s.open_session as usize),
            close_session: core::mem::transmute(s.close_session as usize),
            invoke: core::mem::transmute(s.invoke as usize),
        });
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = s;
        None
    }
}

#[allow(dead_code)]
fn _hal_error(_: HalError) {}
