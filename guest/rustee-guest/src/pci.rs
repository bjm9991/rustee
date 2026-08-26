#![allow(dead_code)]
//! QEMU virt ECAM at 0x4010_0000_0000. Assign 32-bit MMIO from 0x1000_0000.
const ECAM: u64 = 0x4010_0000_0000;
const MMIO_BASE: u64 = 0x1000_0000;

static mut NEXT_MMIO: u64 = MMIO_BASE;

pub const VENDOR_VIRTIO: u16 = 0x1af4;
pub const DEV_VSOCK: u16 = 0x1053;
pub const DEV_RNG: u16 = 0x1044;

fn cfg_ptr(bus: u8, dev: u8, func: u8, off: u16) -> *mut u32 {
    let a = ECAM
        + ((bus as u64) << 20)
        + ((dev as u64) << 15)
        + ((func as u64) << 12)
        + (off as u64);
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
            return Some(PciDev { bus: 0, dev, func: 0, device_id });
        }
    }
    None
}

/// Map BAR `bar` (0, 2, ...) and return MMIO base.
pub unsafe fn map_bar(d: &PciDev, bar: u8) -> u64 {
    let off = 0x10 + bar as u16 * 4;
    cfg_write32(d.bus, d.dev, d.func, off, 0xffff_ffff);
    let sz = cfg_read32(d.bus, d.dev, d.func, off);
    let size = (!(sz & !0xf)).wrapping_add(1) as u64;
    let size = if size == 0 { 0x1000 } else { size.max(0x1000) };
    let base = NEXT_MMIO;
    NEXT_MMIO = (NEXT_MMIO + size + 0xfff) & !0xfff;
    cfg_write32(d.bus, d.dev, d.func, off, base as u32);
    let cmd = cfg_read16(d.bus, d.dev, d.func, 4) as u32;
    cfg_write32(d.bus, d.dev, d.func, 4, cmd | 0x6);
    base
}
