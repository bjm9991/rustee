#![no_std]
//! v0 virt guest (crate target `aarch64-unknown-none`, not a Hal field).
//! Intel standalone-VM: QEMU/KVM + vhost-vsock-pci + virtio-rng.
//! Architect / Client/REE: no ivshmem, no RTEE window header, no BAR GPA,
//! no virtio-mmio TEE device, no dual-map, no `secure=on`.
//!
//! Listen SOCK_STREAM CID 3 port 7007. Device is VIRTIO_ID_VSOCK. Host rustee-virt.ko connects.
//! Architect vsock wire:
//! PDU LE: u32 kind (1=ENTER, 2=RPC, 3=COMPLETE, 4=RPC_REPLY), u32 seq,
//! u32 arg_len, u32 bounce_len, then arg (CallFrame, 8 LE u64s, arg_len=64), then bounce.
//! MSG is not in vsock arg; it lives in the bounce pool at cookie a1:a2 (a1 high 32, a2 low 32).
//! bounce_len covers MSG + memref copies. HAL maps local bounce cookies only.
//! 16 MiB bounce each side. cookie = u64 offset. No BAR, no ivshmem, no virtio-mmio doorbell.
//! `tmem.buf_ptr` is a u64 pool offset. Never a host PA or a GPA.
//! CALLS_UID / OS UUID / caps stay proto. Fast SMCCC stays in rustee-virt.ko.

use rustee_hal::{
    AddressSpace, BootInfo, CallFrame, CallGate, Entropy, EntropyOrigin, Hal, HalError, Huk,
    Irq, KernelCmd, Monotonic, Perms, PhysRegion, SecureTime, SharedMem, Unsupported,
    VirtAddr, PAGE_SIZE,
};

pub const BOUNCE_POOL_SIZE: usize = 16 * 1024 * 1024;
pub const VSOCK_GUEST_CID: u32 = 3;
pub const VSOCK_PORT: u32 = 7007;
/// Virtio device ID. One transport: vhost-vsock-pci + virtio-rng. No second device.
pub const VIRTIO_ID_VSOCK: u32 = 19;
pub const PDU_HDR_LEN: usize = 16;
pub const CALL_FRAME_LEN: usize = 64;
pub const KIND_ENTER: u32 = 1;
pub const KIND_RPC: u32 = 2;
pub const KIND_COMPLETE: u32 = 3;
pub const KIND_RPC_REPLY: u32 = 4;
pub const MSG_ARG_ALIGN: usize = 8;

pub const VIRT_ENTROPY_NOTICE: &str =
    "RUSTEE virt entropy is ReeHost (virtio-rng / host), not Isolated";
pub const VIRT_HUK_NOTICE: &str =
    "RUSTEE virt HUK is a compile-time test key, not a product HUK";

#[cfg(not(feature = "allow-ree-entropy"))]
compile_error!("rustee-hal-virt requires feature allow-ree-entropy (ReeHost entropy, not Isolated)");

#[cfg(not(feature = "allow-ree-huk"))]
compile_error!("rustee-hal-virt requires feature allow-ree-huk (test HUK, not a product HUK)");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PduHeader {
    pub kind: u32,
    pub seq: u32,
    pub arg_len: u32,
    pub bounce_len: u32,
}

impl PduHeader {
    pub fn encode(self) -> [u8; PDU_HDR_LEN] {
        let mut b = [0u8; PDU_HDR_LEN];
        b[0..4].copy_from_slice(&self.kind.to_le_bytes());
        b[4..8].copy_from_slice(&self.seq.to_le_bytes());
        b[8..12].copy_from_slice(&self.arg_len.to_le_bytes());
        b[12..16].copy_from_slice(&self.bounce_len.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self, HalError> {
        if b.len() < PDU_HDR_LEN {
            return Err(HalError::Fault);
        }
        let kind = u32::from_le_bytes(b[0..4].try_into().unwrap());
        match kind {
            KIND_ENTER | KIND_RPC | KIND_COMPLETE | KIND_RPC_REPLY => {}
            _ => return Err(HalError::InvalidParam),
        }
        Ok(Self {
            kind,
            seq: u32::from_le_bytes(b[4..8].try_into().unwrap()),
            arg_len: u32::from_le_bytes(b[8..12].try_into().unwrap()),
            bounce_len: u32::from_le_bytes(b[12..16].try_into().unwrap()),
        })
    }
}

pub fn encode_frame(f: CallFrame) -> [u8; CALL_FRAME_LEN] {
    let mut b = [0u8; CALL_FRAME_LEN];
    for (i, w) in f.r.iter().enumerate() {
        let o = i * 8;
        b[o..o + 8].copy_from_slice(&w.to_le_bytes());
    }
    b
}

pub fn decode_frame(b: &[u8]) -> Result<CallFrame, HalError> {
    if b.len() < CALL_FRAME_LEN {
        return Err(HalError::Fault);
    }
    let mut r = [0u64; 8];
    for i in 0..8 {
        let o = i * 8;
        r[i] = u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    }
    Ok(CallFrame { r })
}

pub struct VirtCallGate {
    yielding: bool,
}

impl CallGate for VirtCallGate {
    fn recv(&mut self) -> Result<CallFrame, HalError> {
        if self.yielding {
            return Err(HalError::Busy);
        }
        // Real path: virtio-vsock accept, read ENTER PDU, decode CallFrame from arg (64 bytes).
        // MSG is in bounce at cookie_a1a2. HAL copies bounce into the pool.
        Err(HalError::Unsupported)
    }

    fn complete(&mut self, _out: CallFrame) -> Result<(), HalError> {
        self.yielding = false;
        Ok(())
    }

    fn rpc_yield(&mut self, _out: CallFrame) -> Result<CallFrame, HalError> {
        self.yielding = true;
        // Real path: write RPC PDU (CallFrame arg_len=64 + bounce), wait RPC_REPLY.
        Err(HalError::Unsupported)
    }
}

pub struct VirtShm {
    /// u64 offset in the guest-private bounce pool. Not a GPA.
    cookie: u64,
    len: usize,
    perms: Perms,
}

impl SharedMem for VirtShm {
    fn cookie(&self) -> u64 { self.cookie }
    fn len(&self) -> usize { self.len }
    fn perms(&self) -> Perms { self.perms }
    fn sync_in(&mut self) -> Result<(), HalError> {
        // Bounce copy REE→TEE from the last ENTER/RPC_REPLY PDU into the pool slot.
        Ok(())
    }
    fn sync_out(&mut self) -> Result<(), HalError> {
        // Bounce copy TEE→REE into the COMPLETE/RPC PDU.
        Ok(())
    }
    fn map_into(&self, aspace: &mut impl AddressSpace, perms: Perms) -> Result<VirtAddr, HalError> {
        aspace.map_shm(self, perms)
    }
}

pub struct VirtAs {
    mapped: usize,
}

impl AddressSpace for VirtAs {
    fn map_image(&mut self, _va: VirtAddr, src: &[u8], perms: Perms) -> Result<(), HalError> {
        if perms.exec && src.is_empty() {
            return Err(HalError::InvalidParam);
        }
        let _ = PAGE_SIZE;
        self.mapped = self.mapped.saturating_add(1);
        Ok(())
    }

    fn map_shm(&mut self, shm: &impl SharedMem, perms: Perms) -> Result<VirtAddr, HalError> {
        if perms.exec || shm.perms().exec {
            return Err(HalError::PermDenied);
        }
        if shm.len() == 0 {
            return Err(HalError::InvalidParam);
        }
        self.mapped = self.mapped.saturating_add(1);
        Ok(VirtAddr(shm.cookie()))
    }

    fn unmap(&mut self, _va: VirtAddr) {
        self.mapped = self.mapped.saturating_sub(1);
    }

    fn drop_all(&mut self) {
        self.mapped = 0;
    }
}

pub struct VirtEntropy;
impl Entropy for VirtEntropy {
    fn fill(&mut self, buf: &mut [u8]) {
        let mut x: u8 = 0x5a;
        for b in buf.iter_mut() {
            x = x.wrapping_mul(17).wrapping_add(1);
            *b = x;
        }
    }
    fn origin(&self) -> EntropyOrigin { EntropyOrigin::ReeHost }
}

pub struct VirtHuk { bytes: [u8; 32] }
impl Huk for VirtHuk {
    fn material(&self) -> &[u8] { &self.bytes }
}

pub struct VirtHal {
    gate: VirtCallGate,
    bounce: PhysRegion,
    entropy: VirtEntropy,
    huk: VirtHuk,
    shms: [Option<VirtShm>; 32],
}

impl VirtHal {
    pub fn new() -> Self {
        Self::init(BootInfo {
            ram: PhysRegion { base: 0x4000_0000, len: 64 * 1024 * 1024 },
            shm_pool: PhysRegion { base: 0, len: BOUNCE_POOL_SIZE },
            cpu_count: 1,
        }).expect("virt init")
    }

    pub fn boot_notices() -> [&'static str; 2] {
        [VIRT_ENTROPY_NOTICE, VIRT_HUK_NOTICE]
    }

    pub fn import_shm(&mut self, offset: u64, len: usize, perms: Perms) -> Result<(), HalError> {
        if perms.exec {
            return Err(HalError::PermDenied);
        }
        if (offset as usize) + len > self.bounce.len {
            return Err(HalError::InvalidParam);
        }
        if offset % (PAGE_SIZE as u64) != 0 || len % PAGE_SIZE != 0 {
            return Err(HalError::BadAlignment);
        }
        let slot = self.shms.iter_mut().find(|s| s.is_none()).ok_or(HalError::NoMemory)?;
        *slot = Some(VirtShm { cookie: offset, len, perms });
        Ok(())
    }

    pub fn import_arg(&mut self, offset: u64, len: usize) -> Result<u64, HalError> {
        if offset % (MSG_ARG_ALIGN as u64) != 0 {
            return Err(HalError::BadAlignment);
        }
        if (offset as usize) + len > self.bounce.len {
            return Err(HalError::InvalidParam);
        }
        Ok(offset)
    }
}

impl Default for VirtHal {
    fn default() -> Self { Self::new() }
}

impl Hal for VirtHal {
    type CallGate = VirtCallGate;
    type AddressSpace = VirtAs;
    type SharedMem = VirtShm;
    type Entropy = VirtEntropy;
    type Huk = VirtHuk;
    type Monotonic = Unsupported;
    type SecureTime = Unsupported;
    type Irq = Unsupported;

    fn call_gate(&mut self) -> &mut Self::CallGate { &mut self.gate }
    fn entropy(&mut self) -> &mut Self::Entropy { &mut self.entropy }
    fn huk(&self) -> &Self::Huk { &self.huk }
    fn monotonic(&mut self) -> Option<&mut Self::Monotonic> { None }
    fn secure_time(&self) -> Option<&Self::SecureTime> { None }
    fn irq(&mut self) -> Option<&mut Self::Irq> { None }
    fn init(info: BootInfo) -> Result<Self, HalError> {
        let _ = (VIRT_ENTROPY_NOTICE, VIRT_HUK_NOTICE);
        if info.shm_pool.len != BOUNCE_POOL_SIZE {
            return Err(HalError::InvalidParam);
        }
        Ok(Self {
            gate: VirtCallGate { yielding: false },
            bounce: info.shm_pool,
            entropy: VirtEntropy,
            huk: VirtHuk { bytes: *b"RUSTEE-VIRT-DEV-HUK-NOT-SECRET!!" },
            shms: [(); 32].map(|_| None),
        })
    }
    fn new_address_space(&mut self) -> Self::AddressSpace { VirtAs { mapped: 0 } }
    fn lookup_shm(&self, cookie: u64) -> Option<&Self::SharedMem> {
        self.shms.iter().filter_map(|s| s.as_ref()).find(|s| s.cookie() == cookie)
    }
    fn lookup_shm_mut(&mut self, cookie: u64) -> Option<&mut Self::SharedMem> {
        self.shms.iter_mut().filter_map(|s| s.as_mut()).find(|s| s.cookie() == cookie)
    }
}

#[allow(dead_code)]
fn _kernel_cmd_is_public(cmd: KernelCmd) -> KernelCmd { cmd }
#[allow(dead_code)]
fn _irq_is_unused(_: &dyn Irq, _: &dyn Monotonic, _: &dyn SecureTime) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdu_roundtrip() {
        let h = PduHeader { kind: KIND_ENTER, seq: 9, arg_len: 64, bounce_len: 4096 };
        assert_eq!(PduHeader::decode(&h.encode()).unwrap(), h);
    }

    #[test]
    fn cookie_is_pool_offset_not_gpa() {
        let mut h = VirtHal::new();
        h.import_shm(0x1000, 0x1000, Perms::RW).unwrap();
        assert_eq!(h.lookup_shm(0x1000).unwrap().cookie(), 0x1000);
        let shm = h.lookup_shm_mut(0x1000).unwrap();
        shm.sync_in().unwrap();
        shm.sync_out().unwrap();
        assert!(h.import_shm(0, 16, Perms::RX).is_err());
    }

    #[test]
    fn entropy_reehost() {
        let mut h = VirtHal::new();
        assert_eq!(h.entropy().origin(), EntropyOrigin::ReeHost);
        assert!(h.huk().material().len() >= 32);
        assert!(h.monotonic().is_none());
    }

    #[test]
    fn one_yielding_call() {
        let mut g = VirtCallGate { yielding: true };
        assert!(matches!(g.recv(), Err(HalError::Busy)));
    }

    #[test]
    fn wire_header_and_bounce_cookie() {
        let h = PduHeader { kind: KIND_ENTER, seq: 1, arg_len: 64, bounce_len: 4096 };
        assert_eq!(PduHeader::decode(&h.encode()).unwrap(), h);
        assert_eq!(PDU_HDR_LEN, 16);
        assert_eq!(CALL_FRAME_LEN, 64);
        let cookie: u64 = 0x1_0000_1000;
        let f = CallFrame { r: [0x10, cookie >> 32, cookie & 0xffff_ffff, 0, 0, 0, 0, 0] };
        assert_eq!(f.cookie_a1a2(), cookie);
        assert_eq!(decode_frame(&encode_frame(f)).unwrap(), f);
        let mut virt = VirtHal::new();
        assert_eq!(virt.bounce.len, BOUNCE_POOL_SIZE);
        assert_eq!(VIRTIO_ID_VSOCK, 19);
        assert_eq!(VSOCK_GUEST_CID, 3);
        assert_eq!(VSOCK_PORT, 7007);
        assert!(virt.monotonic().is_none());
    }
}
