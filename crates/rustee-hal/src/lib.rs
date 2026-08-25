#![no_std]

/// 8 SMCCC-shaped registers. virt serializes this as vsock PDU arg (64 bytes LE).
#[derive(Clone, Copy, Debug, Default)]
pub struct CallFrame {
    pub r: [u64; 8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntropyOrigin {
    Isolated,
    ReeHost,
}

pub trait CallGate {
    type Error;
    fn recv(&mut self) -> Result<CallFrame, Self::Error>;
    fn complete(&mut self, out: CallFrame) -> Result<(), Self::Error>;
    fn rpc_yield(&mut self, out: CallFrame) -> Result<CallFrame, Self::Error>;
}

pub trait Entropy {
    fn fill(&mut self, buf: &mut [u8]);
    fn origin(&self) -> EntropyOrigin;
}

pub trait Huk {
    /// >= 32 bytes, never copied to REE.
    fn material(&self) -> &[u8];
}

pub trait TaAddressSpace {
    type Error;
    fn map_image(&mut self, segments: &[[u64; 2]]) -> Result<(), Self::Error>;
    fn map_shm(&mut self, shm: &impl ShmMapping, perms: u32) -> Result<u64, Self::Error>;
    fn unmap(&mut self, va: u64, len: usize) -> Result<(), Self::Error>;
    fn drop_all(self);
}

pub trait ShmMapping {
    fn cookie(&self) -> u64;
    fn len(&self) -> usize;
    fn perms(&self) -> u32;
}

pub trait SharedMem: ShmMapping {
    type Error;
    fn sync_in(&mut self) -> Result<(), Self::Error>;
    fn sync_out(&mut self) -> Result<(), Self::Error>;
}

/// Isolation HAL. No `rpc` method: outbound RPC is `KernelOut::Rpc` then `CallGate::rpc_yield`.
pub trait Hal: Sized {
    type CallGate: CallGate;
    type AddressSpace: TaAddressSpace;
    type SharedMem: SharedMem;
    type Entropy: Entropy;
    type Huk: Huk;
    type Monotonic;
    type SecureTime;
    type Irq;
    type Error;
}

#[cfg(test)]
mod tests {
    #[test]
    fn callframe_is_64() {
        assert_eq!(core::mem::size_of::<super::CallFrame>(), 64);
    }
}
