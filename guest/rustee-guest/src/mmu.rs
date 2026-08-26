//! Identity map 1 GiB device (0), 1 GiB RAM (0x4000_0000), 1 GiB PCI ECAM (0x40_0000_0000).
use core::arch::asm;

#[repr(C, align(4096))]
struct Table([u64; 512]);

static mut L1: Table = Table([0; 512]);

const AF: u64 = 1 << 10;
const VALID_BLOCK: u64 = 1; // bit0=1, bit1=0 at L1 = block
const ATTR_DEV: u64 = 0 << 2;
const ATTR_MEM: u64 = 1 << 2;
const SH_ISH: u64 = 3 << 8;

unsafe fn map_gb(idx: usize, pa: u64, mem: bool) {
    let attr = if mem { ATTR_MEM | SH_ISH } else { ATTR_DEV };
    L1.0[idx] = pa | VALID_BLOCK | attr | AF;
}

pub unsafe fn enable() {
    map_gb(0, 0, false);
    map_gb(1, 0x4000_0000, true);
    map_gb(256, 0x40_0000_0000, false);

    let mair: u64 = 0x04 | (0xff << 8); // Attr0 device nGnRE, Attr1 normal WB
    let tcr: u64 = (25 << 0) // T0SZ = 39-bit
        | (0b00 << 14) // TG0 4K
        | (0b11 << 12) // Inner WB
        | (0b11 << 10) // Outer WB
        | (0b11 << 8); // Inner shareable
    let ttbr = core::ptr::addr_of!(L1) as u64;

    asm!(
        "msr mair_el1, {mair}",
        "msr tcr_el1, {tcr}",
        "msr ttbr0_el1, {ttbr}",
        "tlbi vmalle1",
        "dsb sy",
        "isb",
        "mrs {tmp}, sctlr_el1",
        "orr {tmp}, {tmp}, #1",
        "orr {tmp}, {tmp}, #(1 << 2)",
        "orr {tmp}, {tmp}, #(1 << 12)",
        "msr sctlr_el1, {tmp}",
        "isb",
        mair = in(reg) mair,
        tcr = in(reg) tcr,
        ttbr = in(reg) ttbr,
        tmp = out(reg) _,
    );
}
