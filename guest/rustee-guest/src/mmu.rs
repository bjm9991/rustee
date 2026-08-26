//! Identity map 1 GiB device (0), 1 GiB RAM (0x4000_0000), PCI ECAM,
//! and 1 GiB high MMIO at 0x8000_0000_0000 (64-bit BARs).
//! 40-bit VA (T0SZ=24) so high MMIO is in range; IPS=40-bit PA.
use core::arch::asm;
use core::ptr::{addr_of, addr_of_mut};

#[repr(C, align(4096))]
struct Table([u64; 512]);

static mut L0: Table = Table([0; 512]);
static mut L1_LOW: Table = Table([0; 512]);
static mut L1_HIGH: Table = Table([0; 512]);

const AF: u64 = 1 << 10;
const VALID_BLOCK: u64 = 1; // bit0=1, bit1=0 = block
const VALID_TABLE: u64 = 0b11;
const ATTR_DEV: u64 = 0 << 2;
const ATTR_MEM: u64 = 1 << 2;
const SH_ISH: u64 = 3 << 8;

unsafe fn map_gb(l1: *mut Table, idx: usize, pa: u64, mem: bool) {
    let attr = if mem { ATTR_MEM | SH_ISH } else { ATTR_DEV };
    (*l1).0[idx] = pa | VALID_BLOCK | attr | AF;
}

pub unsafe fn enable() {
    map_gb(addr_of_mut!(L1_LOW), 0, 0, false);
    map_gb(addr_of_mut!(L1_LOW), 1, 0x4000_0000, true);
    map_gb(addr_of_mut!(L1_LOW), 256, 0x40_0000_0000, false);
    map_gb(addr_of_mut!(L1_HIGH), 0, 0x8000_0000_0000, false);

    (*addr_of_mut!(L0)).0[0] = addr_of!(L1_LOW) as u64 | VALID_TABLE;
    (*addr_of_mut!(L0)).0[1] = addr_of!(L1_HIGH) as u64 | VALID_TABLE;

    let mair: u64 = 0x04 | (0xff << 8); // Attr0 device nGnRE, Attr1 normal WB
    let tcr: u64 = 24 // T0SZ = 40-bit VA
        | (0b00 << 14) // TG0 4K
        | (0b11 << 12) // Inner WB
        | (0b11 << 10) // Outer WB
        | (0b11 << 8) // Inner shareable
        | (0b010 << 32); // IPS 40-bit PA
    let ttbr = addr_of!(L0) as u64;

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
