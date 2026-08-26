#![allow(dead_code)]
//! QEMU virt ECAM at 0x40_1000_0000. 32-bit MMIO from 0x1000_0000;
//! 64-bit BARs from high MMIO 0x8000_0000_0000.
use core::ptr::{addr_of, addr_of_mut};

const ECAM: u64 = 0x40_1000_0000;
const MMIO32_BASE: u64 = 0x1000_0000;
const MMIO32_END: u64 = 0x3e00_0000;
const MMIO64_BASE: u64 = 0x8000_0000_0000;
const MMIO64_END: u64 = 0x8000_0000_0000 + 0x4000_0000;

static mut NEXT_MMIO32: u64 = MMIO32_BASE;
static mut NEXT_MMIO64: u64 = MMIO64_BASE;

#[derive(Clone, Copy)]
struct BarCache {
    bus: u8,
    dev: u8,
    func: u8,
    bar: u8,
    base: u64,
}

static mut BAR_CACHE: [Option<BarCache>; 24] = [None; 24];

pub const VENDOR_VIRTIO: u16 = 0x1af4;
pub const DEV_VSOCK: u16 = 0x1053;
pub const DEV_RNG: u16 = 0x1044;

fn cfg_ptr(bus: u8, dev: u8, func: u8, off: u16) -> *mut u32 {
    let a =
        ECAM + ((bus as u64) << 20) + ((dev as u64) << 15) + ((func as u64) << 12) + (off as u64);
    a as *mut u32
}

pub unsafe fn cfg_read32(bus: u8, dev: u8, func: u8, off: u16) -> u32 {
    core::ptr::read_volatile(cfg_ptr(bus, dev, func, off))
}
pub unsafe fn cfg_write32(bus: u8, dev: u8, func: u8, off: u16, v: u32) {
    core::ptr::write_volatile(cfg_ptr(bus, dev, func, off), v);
}
pub unsafe fn cfg_read8(bus: u8, dev: u8, func: u8, off: u16) -> u8 {
    let w = cfg_read32(bus, dev, func, off & !3);
    ((w >> ((off & 3) * 8)) & 0xff) as u8
}
pub unsafe fn cfg_read16(bus: u8, dev: u8, func: u8, off: u16) -> u16 {
    let w = cfg_read32(bus, dev, func, off & !3);
    ((w >> ((off & 3) * 8)) & 0xffff) as u16
}

#[derive(Clone, Copy)]
pub struct PciDev {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub device_id: u16,
}

pub unsafe fn find(device_id: u16) -> Option<PciDev> {
    for dev in 0..32u8 {
        let id = cfg_read32(0, dev, 0, 0);
        if id == 0xffff_ffff {
            continue;
        }
        let vendor = (id & 0xffff) as u16;
        let device = (id >> 16) as u16;
        if vendor == VENDOR_VIRTIO && device == device_id {
            return Some(PciDev {
                bus: 0,
                dev,
                func: 0,
                device_id,
            });
        }
    }
    None
}

unsafe fn cached(d: &PciDev, bar: u8) -> Option<u64> {
    let cache = &*addr_of!(BAR_CACHE);
    for slot in cache.iter() {
        if let Some(c) = slot {
            if c.bus == d.bus && c.dev == d.dev && c.func == d.func && c.bar == bar {
                return Some(c.base);
            }
        }
    }
    None
}

unsafe fn remember(d: &PciDev, bar: u8, base: u64) {
    let cache = &mut *addr_of_mut!(BAR_CACHE);
    for slot in cache.iter_mut() {
        if slot.is_none() {
            *slot = Some(BarCache {
                bus: d.bus,
                dev: d.dev,
                func: d.func,
                bar,
                base,
            });
            return;
        }
    }
}

fn align_up(addr: u64, align: u64) -> u64 {
    if align <= 1 {
        return addr;
    }
    (addr + align - 1) & !(align - 1)
}

unsafe fn alloc_mmio(size: u64, _is_64: bool) -> u64 {
    // 64-bit BARs still take a 32-bit address (high dword 0) in QEMU virt's
    // PCI MMIO window at 0x10000000, which is identity-mapped. Assigning
    // 0x8000000000 hung qemu-smoke on the first common-cfg access after #40.
    let size = size.max(0x1000);
    let cur = addr_of_mut!(NEXT_MMIO32);
    let base = align_up(*cur, size);
    let next = base.saturating_add(size);
    if next > MMIO32_END {
        crate::uart::fail_halt("32-bit MMIO window exhausted");
    }
    *cur = next;
    base
}

unsafe fn enable_mem_busmaster(d: &PciDev) {
    let cmd = cfg_read16(d.bus, d.dev, d.func, 4) as u32;
    cfg_write32(d.bus, d.dev, d.func, 4, cmd | 0x6);
}

/// Map BAR `bar` (0..5) and return MMIO base. Handles 64-bit BARs (type bit 2).
/// I/O BARs (`orig_lo & 1`) return `None` — QEMU virtio-pci BAR0 is legacy PIO;
/// modern common/notify/device live in a memory BAR. Do not halt.
pub unsafe fn map_bar(d: &PciDev, bar: u8) -> Option<u64> {
    if let Some(b) = cached(d, bar) {
        return Some(b);
    }
    let off = 0x10 + bar as u16 * 4;
    let orig_lo = cfg_read32(d.bus, d.dev, d.func, off);
    if orig_lo & 1 != 0 {
        return None;
    }
    let is_64 = (orig_lo & 0x6) == 0x4;
    let size = if is_64 {
        if bar >= 5 {
            crate::uart::fail_halt("64-bit BAR overflows BAR list");
        }
        let hi_off = off + 4;
        cfg_write32(d.bus, d.dev, d.func, off, 0xffff_ffff);
        cfg_write32(d.bus, d.dev, d.func, hi_off, 0xffff_ffff);
        let sz_lo = cfg_read32(d.bus, d.dev, d.func, off) as u64;
        let sz_hi = cfg_read32(d.bus, d.dev, d.func, hi_off) as u64;
        let sz = (sz_hi << 32) | sz_lo;
        let size = (!(sz & !0xf)).wrapping_add(1);
        if size == 0 {
            0x1000
        } else {
            size.max(0x1000)
        }
    } else {
        cfg_write32(d.bus, d.dev, d.func, off, 0xffff_ffff);
        let sz = cfg_read32(d.bus, d.dev, d.func, off);
        let size = (!(sz & !0xf)).wrapping_add(1) as u64;
        if size == 0 {
            0x1000
        } else {
            size.max(0x1000)
        }
    };
    let base = alloc_mmio(size, is_64);
    cfg_write32(d.bus, d.dev, d.func, off, (base as u32 & !0xf) | (orig_lo & 0xf));
    if is_64 {
        cfg_write32(d.bus, d.dev, d.func, off + 4, (base >> 32) as u32);
        remember(d, bar, base);
        remember(d, bar + 1, base);
    } else {
        remember(d, bar, base);
    }
    enable_mem_busmaster(d);
    Some(base)
}
