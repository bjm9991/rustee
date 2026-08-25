#![no_std]

//! v0 virt: QEMU/KVM + vhost-vsock-pci (CID 3 port 7007) + bounce pool.
//! Not ivshmem. Guest target is crate metadata, not a trait field.

use rustee_hal::{CallFrame, CallGate, Entropy, EntropyOrigin, Huk};

pub const VSOCK_CID: u32 = 3;
pub const VSOCK_PORT: u32 = 7007;
pub const BOUNCE_BYTES: usize = 16 * 1024 * 1024;

pub const VIRT_ENTROPY_NOTICE: &str =
    "RUSTEE entropy is REE-sourced (virt/host); not a product TEE RNG";
pub const VIRT_HUK_NOTICE: &str =
    "RUSTEE HUK is a compile-time test key (virt); not a product HUK";

#[cfg(not(feature = "allow-ree-entropy"))]
compile_error!("virt requires feature allow-ree-entropy");
#[cfg(not(feature = "allow-ree-huk"))]
compile_error!("virt requires feature allow-ree-huk");

pub struct VirtEntropy;
impl Entropy for VirtEntropy {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = 0;
        }
    }
    fn origin(&self) -> EntropyOrigin {
        EntropyOrigin::ReeHost
    }
}

pub struct VirtHuk;
impl Huk for VirtHuk {
    fn material(&self) -> &[u8] {
        &[0u8; 32]
    }
}

pub fn boot_notices() -> [&'static str; 2] {
    [VIRT_ENTROPY_NOTICE, VIRT_HUK_NOTICE]
}

/// Placeholder CallGate. Real virt backend yields over vsock.
pub struct VirtCallGate;
impl CallGate for VirtCallGate {
    type Error = ();
    fn recv(&mut self) -> Result<CallFrame, ()> {
        Err(())
    }
    fn complete(&mut self, _out: CallFrame) -> Result<(), ()> {
        Err(())
    }
    fn rpc_yield(&mut self, _out: CallFrame) -> Result<CallFrame, ()> {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustee_hal::Entropy;
    #[test]
    fn ree_host() {
        assert_eq!(VirtEntropy.origin(), EntropyOrigin::ReeHost);
        assert_eq!(VirtHuk.material().len(), 32);
        assert_eq!(boot_notices().len(), 2);
    }
}
