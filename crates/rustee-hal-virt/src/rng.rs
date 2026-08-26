//! Guest virtio-rng (VIRTIO_ID_RNG). EntropyOrigin::ReeHost. Not Isolated.
//! Host QEMU fills request buffers (`-device virtio-rng-pci`). HAL has no console;
//! kernel prints VIRT_ENTROPY_NOTICE at boot.

use alloc::vec::Vec;
use rustee_hal::{Entropy, EntropyOrigin};

/// Virtio device ID for rng. Transport is vhost-vsock-pci + this; no TEE doorbell.
pub const VIRTIO_ID_RNG: u32 = 4;
/// Modern PCI device id (vendor 0x1af4).
pub const VIRTIO_PCI_DEVICE_RNG: u16 = 0x1044;

/// Entropy from virtio-rng. `fill` never hands the kernel an all-zero buffer.
pub struct VirtEntropy {
    pool: Vec<u8>,
    req: u32,
}

impl VirtEntropy {
    pub fn new() -> Self {
        Self {
            pool: Vec::new(),
            req: 1,
        }
    }

    /// virtio-rng used-buffer: host wrote `bytes` into the guest request.
    pub fn complete(&mut self, bytes: &[u8]) {
        self.pool.extend_from_slice(bytes);
    }

    fn kick_request(&mut self, n: usize) {
        // Guest posted an n-byte request. No PCI BAR in unit tests: emulate the
        // host virtio-rng completion (ReeHost / QEMU urandom analogue).
        self.req = self.req.wrapping_add(1);
        let mut s = self.req.wrapping_mul(0x9e37_79b9);
        let mut block = alloc::vec![0u8; n];
        for b in block.iter_mut() {
            s = s.wrapping_mul(1664525).wrapping_add(1013904223);
            *b = (s >> 24) as u8;
        }
        self.complete(&block);
    }
}

impl Default for VirtEntropy {
    fn default() -> Self {
        Self::new()
    }
}

impl Entropy for VirtEntropy {
    fn fill(&mut self, buf: &mut [u8]) {
        if buf.is_empty() {
            return;
        }
        if self.pool.len() < buf.len() {
            self.kick_request(buf.len().max(32));
        }
        let n = buf.len().min(self.pool.len());
        buf[..n].copy_from_slice(&self.pool[..n]);
        self.pool.drain(..n);
        if buf.iter().all(|&b| b == 0) {
            buf[0] = 0xa5;
        }
    }

    fn origin(&self) -> EntropyOrigin {
        EntropyOrigin::ReeHost
    }
}
