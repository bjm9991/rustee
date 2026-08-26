//! QEMU virt PL011 at 0x0900_0000.
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
