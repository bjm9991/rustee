#![no_std]
//! tz-aarch64 stub. Same [`rustee_hal::Hal`] associated types. No SMC, no assembler.

use rustee_hal::{
    AddressSpace, BootInfo, CallFrame, CallGate, Entropy, EntropyOrigin, Hal, HalError, Huk,
    Irq, Monotonic, Perms, SecureTime, SharedMem, Unsupported, VirtAddr,
};

pub struct TzGate;
impl CallGate for TzGate {
    fn recv(&mut self) -> Result<CallFrame, HalError> { Err(HalError::Unsupported) }
    fn complete(&mut self, _: CallFrame) -> Result<(), HalError> { Err(HalError::Unsupported) }
    fn rpc_yield(&mut self, _: CallFrame) -> Result<CallFrame, HalError> { Err(HalError::Unsupported) }
}

pub struct TzShm;
impl SharedMem for TzShm {
    fn cookie(&self) -> u64 { 0 }
    fn len(&self) -> usize { 0 }
    fn perms(&self) -> Perms { Perms::READ }
    fn sync_in(&mut self) -> Result<(), HalError> { Ok(()) } // dual-map: no-op / cache later
    fn sync_out(&mut self) -> Result<(), HalError> { Ok(()) }
    fn map_into(&self, aspace: &mut impl AddressSpace, perms: Perms) -> Result<VirtAddr, HalError> {
        aspace.map_shm(self, perms)
    }
}

pub struct TzAs;
impl AddressSpace for TzAs {
    fn map_image(&mut self, _: VirtAddr, _: &[u8], _: Perms) -> Result<(), HalError> {
        Err(HalError::Unsupported)
    }
    fn map_shm(&mut self, _: &impl SharedMem, _: Perms) -> Result<VirtAddr, HalError> {
        Err(HalError::Unsupported)
    }
    fn unmap(&mut self, _: VirtAddr) {}
    fn drop_all(&mut self) {}
}

pub struct TzEntropy;
impl Entropy for TzEntropy {
    fn fill(&mut self, _: &mut [u8]) {}
    fn origin(&self) -> EntropyOrigin { EntropyOrigin::Isolated }
}

pub struct TzHuk { bytes: [u8; 32] }
impl Huk for TzHuk {
    fn material(&self) -> &[u8] { &self.bytes }
}

pub struct TzHal {
    gate: TzGate,
    entropy: TzEntropy,
    huk: TzHuk,
}

impl Default for TzHal {
    fn default() -> Self {
        Self { gate: TzGate, entropy: TzEntropy, huk: TzHuk { bytes: [0; 32] } }
    }
}

impl Hal for TzHal {
    type CallGate = TzGate;
    type AddressSpace = TzAs;
    type SharedMem = TzShm;
    type Entropy = TzEntropy;
    type Huk = TzHuk;
    type Monotonic = Unsupported;
    type SecureTime = Unsupported;
    type Irq = Unsupported;

    fn call_gate(&mut self) -> &mut Self::CallGate { &mut self.gate }
    fn entropy(&mut self) -> &mut Self::Entropy { &mut self.entropy }
    fn huk(&self) -> &Self::Huk { &self.huk }
    fn monotonic(&mut self) -> Option<&mut Self::Monotonic> { None }
    fn secure_time(&self) -> Option<&Self::SecureTime> { None }
    fn irq(&mut self) -> Option<&mut Self::Irq> { None }
    fn init(_info: BootInfo) -> Result<Self, HalError> { Ok(Self::default()) }
    fn new_address_space(&mut self) -> Self::AddressSpace { TzAs }
    fn lookup_shm(&self, _: u64) -> Option<&Self::SharedMem> { None }
    fn lookup_shm_mut(&mut self, _: u64) -> Option<&mut Self::SharedMem> { None }
}

#[allow(dead_code)]
fn _unused_irq(_: &dyn Irq, _: &dyn Monotonic, _: &dyn SecureTime) {}
