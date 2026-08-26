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

/// Cap a v0 TA image. Hello-rs is well under this; bigger TAs are a later profile.
const MAX_TA_SPAN: usize = 16 * 1024 * 1024;

/// Map PT_LOAD into the TA aspace as one contiguous blob so text/data keep a
/// single slide (aarch64 ADRP is PC-relative). BSS is zero-filled to mem_size.
/// On aarch64, bind GP TA_* as `symbol + (mapped_va - min_va)`.
pub fn map_elf<A: AddressSpace>(aspace: &mut A, bytes: &[u8]) -> Result<Option<TaEntryPoints>, u32> {
    let img = parse_elf(bytes)?;
    if img.segs.is_empty() {
        return Ok(bind_symbols(img.symbols, 0));
    }
    let min_va = img.segs.iter().map(|s| s.va).min().unwrap();
    let max_end = img
        .segs
        .iter()
        .map(|s| s.va.saturating_add(s.mem_size.max(s.file_size) as u64))
        .max()
        .unwrap();
    let span = max_end
        .checked_sub(min_va)
        .ok_or(TEE_ERROR_BAD_PARAMETERS)? as usize;
    if span == 0 || span > MAX_TA_SPAN {
        return Err(TEE_ERROR_BAD_PARAMETERS);
    }
    let mut blob = alloc::vec![0u8; span];
    for seg in &img.segs {
        let off = (seg.va - min_va) as usize;
        let n = seg.file_size.min(seg.mem_size);
        let end = seg.file_off.saturating_add(n);
        let src = bytes
            .get(seg.file_off..end)
            .ok_or(TEE_ERROR_BAD_PARAMETERS)?;
        let dest = off.checked_add(n).ok_or(TEE_ERROR_BAD_PARAMETERS)?;
        if dest > blob.len() {
            return Err(TEE_ERROR_BAD_PARAMETERS);
        }
        blob[off..dest].copy_from_slice(src);
    }
    let mapped = aspace
        .map_image(VirtAddr(min_va), &blob, Perms::RX)
        .map_err(|_| TEE_ERROR_BAD_PARAMETERS)?;
    let slide = mapped.0.wrapping_sub(min_va);
    Ok(bind_symbols(img.symbols, slide))
}

fn bind_symbols(symbols: Option<TaSymbols>, slide: u64) -> Option<TaEntryPoints> {
    let s = symbols?;
    let adj = |v: u64| v.wrapping_add(slide) as usize;
    #[cfg(target_arch = "aarch64")]
    unsafe {
        return Some(TaEntryPoints {
            create: core::mem::transmute(adj(s.create)),
            destroy: core::mem::transmute(adj(s.destroy)),
            open_session: core::mem::transmute(adj(s.open_session)),
            close_session: core::mem::transmute(adj(s.close_session)),
            invoke: core::mem::transmute(adj(s.invoke)),
        });
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (s, adj);
        None
    }
}

#[allow(dead_code)]
fn _hal_error(_: HalError) {}

#[cfg(test)]
mod map_tests {
    use super::*;
    use crate::header::{encode_ta_head, TaProperties};
    use crate::abi::Uuid;
    use rustee_hal::{HalError, SharedMem};

    struct RecAs {
        va: u64,
        blob: alloc::vec::Vec<u8>,
        load: u64,
    }

    impl AddressSpace for RecAs {
        fn map_image(
            &mut self,
            va: VirtAddr,
            src: &[u8],
            _: Perms,
        ) -> Result<VirtAddr, HalError> {
            self.va = va.0;
            self.blob = src.to_vec();
            Ok(VirtAddr(self.load))
        }
        fn map_shm(&mut self, _: &impl SharedMem, _: Perms) -> Result<VirtAddr, HalError> {
            Err(HalError::Unsupported)
        }
        fn unmap(&mut self, _: VirtAddr) {}
        fn drop_all(&mut self) {}
    }

    fn put_u16(b: &mut [u8], o: usize, v: u16) {
        b[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u32(b: &mut [u8], o: usize, v: u32) {
        b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u64(b: &mut [u8], o: usize, v: u64) {
        b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// ELF64 LE, one PT_LOAD at 0x10000 covering the file, memsz = filesz+16,
    /// `.rustee.ta_head` section with a valid RTAH.
    fn loadable_elf() -> alloc::vec::Vec<u8> {
        let props = TaProperties {
            uuid: Uuid([9; 16]),
            stack_size: 4096,
            data_size: 4096,
            single_instance: true,
            multi_session: true,
            instance_keep_alive: false,
            endian: 0,
            ta_version: 1,
        };
        let head = encode_ta_head(&props);
        let shstr = b"\0.rustee.ta_head\0.shstrtab\0";
        let ehdr = 64usize;
        let phdr = 56usize;
        let shstr_off = ehdr + phdr;
        let head_off = shstr_off + shstr.len();
        let shoff = (head_off + 40 + 7) & !7;
        let shnum = 3usize;
        let file_sz = shoff + shnum * 64;
        let mut b = alloc::vec![0u8; file_sz];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[6] = 1;
        put_u16(&mut b, 16, 2); // ET_EXEC
        put_u16(&mut b, 18, 183); // EM_AARCH64
        put_u32(&mut b, 20, 1);
        put_u64(&mut b, 24, 0x10000);
        put_u64(&mut b, 32, ehdr as u64); // phoff
        put_u64(&mut b, 40, shoff as u64);
        put_u16(&mut b, 52, 64);
        put_u16(&mut b, 54, 56);
        put_u16(&mut b, 56, 1);
        put_u16(&mut b, 58, 64);
        put_u16(&mut b, 60, shnum as u16);
        put_u16(&mut b, 62, 2); // shstrndx
        // PT_LOAD
        put_u32(&mut b, ehdr, 1);
        put_u32(&mut b, ehdr + 4, 5); // RX
        put_u64(&mut b, ehdr + 8, 0);
        put_u64(&mut b, ehdr + 16, 0x10000);
        put_u64(&mut b, ehdr + 24, 0x10000);
        put_u64(&mut b, ehdr + 32, file_sz as u64);
        put_u64(&mut b, ehdr + 40, (file_sz + 16) as u64);
        put_u64(&mut b, ehdr + 48, 0x1000);
        b[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);
        b[head_off..head_off + 40].copy_from_slice(&head);
        // shdr 0 null
        // shdr 1 .rustee.ta_head
        let s1 = shoff + 64;
        put_u32(&mut b, s1, 1); // name off
        put_u32(&mut b, s1 + 4, 1); // SHT_PROGBITS
        put_u64(&mut b, s1 + 24, head_off as u64);
        put_u64(&mut b, s1 + 32, 40);
        // shdr 2 .shstrtab
        let s2 = shoff + 128;
        put_u32(&mut b, s2, 18); // name off of .shstrtab
        put_u32(&mut b, s2 + 4, 3); // SHT_STRTAB
        put_u64(&mut b, s2 + 24, shstr_off as u64);
        put_u64(&mut b, s2 + 32, shstr.len() as u64);
        b
    }

    #[test]
    fn map_elf_copies_bss_and_slides() {
        let elf = loadable_elf();
        let filesz = elf.len();
        let mut aspace = RecAs {
            va: 0,
            blob: alloc::vec::Vec::new(),
            load: 0x5000_0000,
        };
        let entries = map_elf(&mut aspace, &elf).unwrap();
        assert!(entries.is_none(), "host tests are not aarch64 bind");
        assert_eq!(aspace.va, 0x10000);
        assert_eq!(aspace.blob.len(), filesz + 16);
        assert_eq!(&aspace.blob[filesz..], &[0u8; 16]);
        assert_eq!(&aspace.blob[..4], b"\x7fELF");
    }
}
