//! QEMU virt PL011 at 0x0900_0000.
use core::fmt::Write;

const UART: *mut u32 = 0x0900_0000 as *mut u32;
const UARTFR: *mut u32 = 0x0900_0018 as *mut u32;
const TXFF: u32 = 1 << 5;

pub struct Uart;

impl Uart {
    pub fn write_byte(&mut self, b: u8) {
        unsafe {
            while UARTFR.read_volatile() & TXFF != 0 {}
            UART.write_volatile(b as u32);
        }
    }
}

impl core::fmt::Write for Uart {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(b);
        }
        Ok(())
    }
}

/// Print `msg` on UART and halt. Used for probe / FEATURES_OK failures.
pub fn fail_halt(msg: &str) -> ! {
    let mut u = Uart;
    let _ = writeln!(u, "{msg}");
    loop {
        unsafe { core::arch::asm!("wfe") }
    }
}

/// EL1 sync abort (TA jump to unmapped VA, alignment, etc.).
pub fn fail_halt_fmt(esr: u64, elr: u64, far: u64) -> ! {
    let mut u = Uart;
    let _ = writeln!(u, "sync-el1 esr={esr:#x} elr={elr:#x} far={far:#x}");
    loop {
        unsafe { core::arch::asm!("wfe") }
    }
}
