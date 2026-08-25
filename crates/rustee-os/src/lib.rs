#![no_std]
//! Privileged TEE kernel. `Kernel<H: Hal, C: CryptoProvider>`.
//! Does not speak MSG. Inbound: CallGate::recv → proto → handle.
//! Outbound RPC: KernelOut::Rpc then CallGate::rpc_yield. No Hal::rpc.
extern crate alloc;

use rustee_crypto::CryptoProvider;
use rustee_hal::Hal;

pub struct Uuid(pub [u8; 16]);
pub struct SessionId(pub u32);

pub enum KernelCmd {
    OpenSession,
    Invoke,
    CloseSession,
    Cancel,
    RpcComplete,
}

pub enum HalRpc {
    LoadTa { uuid: Uuid },
    GetTime,
    Fs,
    ShmAlloc,
    ShmFree,
}

pub enum KernelOut {
    Done { result: u32 },
    Rpc(HalRpc),
}

pub struct Kernel<H: Hal, C: CryptoProvider> {
    _h: core::marker::PhantomData<H>,
    _c: core::marker::PhantomData<C>,
}

impl<H: Hal, C: CryptoProvider> Kernel<H, C> {
    pub fn handle(&mut self, _cmd: KernelCmd) -> KernelOut {
        KernelOut::Done { result: 0 }
    }
}
