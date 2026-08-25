#![no_std]
//! tz-aarch64 stub. Same Hal associated types; methods return unsupported.

use rustee_hal::{Entropy, EntropyOrigin, Huk};

pub struct TzEntropy;
impl Entropy for TzEntropy {
    fn fill(&mut self, buf: &mut [u8]) {
        let _ = buf;
    }
    fn origin(&self) -> EntropyOrigin {
        EntropyOrigin::Isolated
    }
}

pub struct TzHuk;
impl Huk for TzHuk {
    fn material(&self) -> &[u8] {
        &[0u8; 32]
    }
}
