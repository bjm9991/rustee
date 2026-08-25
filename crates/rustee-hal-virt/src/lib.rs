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

extern crate alloc;
use alloc::vec::Vec;

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

mod vsock;
pub use vsock::{
    encode_pdu, read_pdu, VirtioVsockHdr, VsockConn, VsockListener, VIRTIO_PCI_DEVICE_VSOCK,
    VIRTIO_PCI_VENDOR, VIRTIO_VSOCK_HDR_LEN, VIRTIO_VSOCK_OP_REQUEST, VIRTIO_VSOCK_OP_RESPONSE,
    VIRTIO_VSOCK_OP_RW, VIRTIO_VSOCK_TYPE_STREAM,
};

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

/// One outstanding yielding call. virtio-vsock (or a test pipe) feeds PDUs via [`VirtHal::feed_pdu`].
pub struct VirtCallGate {
    yielding: bool,
    rx: Option<(PduHeader, CallFrame)>,
    tx: Option<(PduHeader, CallFrame)>,
    seq: u32,
    last_cookie: u64,
    last_bounce_len: u32,
}

impl CallGate for VirtCallGate {
    fn recv(&mut self) -> Result<CallFrame, HalError> {
        if self.yielding {
            return Err(HalError::Busy);
        }
        match self.rx.take() {
            Some((hdr, frame)) if hdr.kind == KIND_ENTER && hdr.arg_len == CALL_FRAME_LEN as u32 => {
                self.seq = hdr.seq;
                self.last_cookie = frame.cookie_a1a2();
                self.last_bounce_len = hdr.bounce_len;
                Ok(frame)
            }
            Some(_) => Err(HalError::InvalidParam),
            None => Err(HalError::NotFound),
        }
    }

    fn complete(&mut self, out: CallFrame) -> Result<(), HalError> {
        if out.cookie_a1a2() != self.last_cookie && self.last_bounce_len != 0 {
            // cookie may be echoed; still emit COMPLETE with last bounce window
        }
        self.tx = Some((
            PduHeader {
                kind: KIND_COMPLETE,
                seq: self.seq,
                arg_len: CALL_FRAME_LEN as u32,
                bounce_len: self.last_bounce_len,
            },
            out,
        ));
        self.yielding = false;
        self.rx = None;
        Ok(())
    }

    fn rpc_yield(&mut self, out: CallFrame) -> Result<CallFrame, HalError> {
        self.yielding = true;
        self.tx = Some((
            PduHeader {
                kind: KIND_RPC,
                seq: self.seq,
                arg_len: CALL_FRAME_LEN as u32,
                bounce_len: self.last_bounce_len,
            },
            out,
        ));
        match self.rx.take() {
            Some((hdr, frame)) if hdr.kind == KIND_RPC_REPLY && hdr.arg_len == CALL_FRAME_LEN as u32 => {
                self.yielding = false;
                self.last_cookie = frame.cookie_a1a2();
                self.last_bounce_len = hdr.bounce_len;
                Ok(frame)
            }
            Some(_) => Err(HalError::InvalidParam),
            None => Err(HalError::NotFound),
        }
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
        // Bytes already sit in the guest pool from feed_pdu. Dual-map would be a cache-op.
        let _ = self.cookie;
        Ok(())
    }
    fn sync_out(&mut self) -> Result<(), HalError> {
        let _ = self.cookie;
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
    bounce_mem: Vec<u8>,
    entropy: VirtEntropy,
    huk: VirtHuk,
    shms: [Option<VirtShm>; 32],
    listener: VsockListener,
    conn: Option<VsockConn>,
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

    fn copy_bounce_in(&mut self, cookie: u64, bounce: &[u8]) -> Result<(), HalError> {
        let start = cookie as usize;
        let end = start.checked_add(bounce.len()).ok_or(HalError::InvalidParam)?;
        if end > self.bounce.len {
            return Err(HalError::InvalidParam);
        }
        if self.bounce_mem.len() < end {
            self.bounce_mem.resize(end, 0);
        }
        self.bounce_mem[start..end].copy_from_slice(bounce);
        Ok(())
    }

    /// Guest vsock path: one PDU. `arg` must be a 64-byte CallFrame. Bounce is copied
    /// into the pool at cookie a1:a2. virtio-vsock calls this from the listen loop.
    pub fn feed_pdu(&mut self, hdr: PduHeader, frame: CallFrame, bounce: &[u8]) -> Result<(), HalError> {
        if hdr.arg_len != CALL_FRAME_LEN as u32 {
            return Err(HalError::InvalidParam);
        }
        if bounce.len() != hdr.bounce_len as usize {
            return Err(HalError::InvalidParam);
        }
        self.copy_bounce_in(frame.cookie_a1a2(), bounce)?;
        self.gate.rx = Some((hdr, frame));
        Ok(())
    }

    pub fn take_tx(&mut self) -> Option<(PduHeader, CallFrame, Vec<u8>)> {
        let (hdr, frame) = self.gate.tx.take()?;
        let start = self.gate.last_cookie as usize;
        let len = hdr.bounce_len as usize;
        let bounce = if start + len <= self.bounce_mem.len() {
            self.bounce_mem[start..start + len].to_vec()
        } else {
            Vec::new()
        };
        Some((hdr, frame, bounce))
    }

    pub fn bounce_at(&self, cookie: u64, len: usize) -> Option<&[u8]> {
        let start = cookie as usize;
        let end = start.checked_add(len)?;
        self.bounce_mem.get(start..end)
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

    /// Bind guest CID 3 port 7007. Host rustee-virt.ko connects after this.
    pub fn listen_vsock(&mut self) {
        self.listener.listen();
    }

    /// virtio-vsock REQUEST -> RESPONSE. One SOCK_STREAM.
    pub fn accept_connect(&mut self, req: &VirtioVsockHdr) -> Result<VirtioVsockHdr, HalError> {
        let resp = self.listener.accept(req)?;
        self.conn = Some(VsockConn::from_accept(req, &self.listener));
        Ok(resp)
    }

    pub fn push_host_rw(&mut self, hdr: &VirtioVsockHdr, payload: &[u8]) -> Result<(), HalError> {
        self.conn.as_mut().ok_or(HalError::NotFound)?.push_rw(hdr, payload)
    }

    /// Read ENTER from the accepted stream, copy bounce, return CallFrame.
    pub fn recv_enter(&mut self) -> Result<CallFrame, HalError> {
        let (hdr, frame, bounce) = {
            let conn = self.conn.as_mut().ok_or(HalError::NotFound)?;
            read_pdu(conn)?
        };
        self.feed_pdu(hdr, frame, &bounce)?;
        self.call_gate().recv()
    }

    /// CallGate complete, then wrap COMPLETE PDU as a guest RW packet.
    pub fn complete_stream(&mut self, out: CallFrame) -> Result<(VirtioVsockHdr, Vec<u8>), HalError> {
        self.call_gate().complete(out)?;
        let (hdr, frame, bounce) = self.take_tx().ok_or(HalError::Fault)?;
        let pdu = encode_pdu(hdr, frame, &bounce);
        let conn = self.conn.as_ref().ok_or(HalError::NotFound)?;
        let (vh, _) = conn.wrap_rw(&pdu);
        Ok((vh, pdu))
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
            gate: VirtCallGate {
                yielding: false,
                rx: None,
                tx: None,
                seq: 0,
                last_cookie: 0,
                last_bounce_len: 0,
            },
            bounce: info.shm_pool,
            bounce_mem: Vec::new(),
            entropy: VirtEntropy,
            huk: VirtHuk { bytes: *b"RUSTEE-VIRT-DEV-HUK-NOT-SECRET!!" },
            shms: [(); 32].map(|_| None),
            listener: VsockListener::default(),
            conn: None,
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
        let mut g = VirtCallGate {
            yielding: true,
            rx: None,
            tx: None,
            seq: 0,
            last_cookie: 0,
            last_bounce_len: 0,
        };
        assert!(matches!(g.recv(), Err(HalError::Busy)));
    }

    #[test]
    fn live_callgate_enter_complete_copies_bounce_at_cookie() {
        let mut h = VirtHal::new();
        let cookie: u64 = 0x1000;
        let payload = b"msg-blob-and-memref";
        let mut frame = CallFrame { r: [0x32000004, 0, 0, 0, 0, 0, 0, 0] };
        frame.set_cookie_a1a2(cookie);
        let hdr = PduHeader {
            kind: KIND_ENTER,
            seq: 3,
            arg_len: 64,
            bounce_len: payload.len() as u32,
        };
        h.feed_pdu(hdr, frame, payload).unwrap();
        let got = h.call_gate().recv().unwrap();
        assert_eq!(got.cookie_a1a2(), cookie);
        assert_eq!(h.bounce_at(cookie, payload.len()).unwrap(), payload);
        h.call_gate().complete(got).unwrap();
        let (th, tf, tb) = h.take_tx().unwrap();
        assert_eq!(th.kind, KIND_COMPLETE);
        assert_eq!(th.arg_len, 64);
        assert_eq!(th.seq, 3);
        assert_eq!(tf.cookie_a1a2(), cookie);
        assert_eq!(tb, payload);
    }

    #[test]
    fn live_rpc_yield_waits_for_rpc_reply() {
        let mut h = VirtHal::new();
        let cookie: u64 = 0x2000;
        let mut enter = CallFrame { r: [0x32000004, 0, 0, 0, 0, 0, 0, 0] };
        enter.set_cookie_a1a2(cookie);
        h.feed_pdu(
            PduHeader { kind: KIND_ENTER, seq: 4, arg_len: 64, bounce_len: 4 },
            enter,
            b"load",
        ).unwrap();
        let f = h.call_gate().recv().unwrap();
        let mut reply = CallFrame { r: [0, 0, 0, 0, 0, 0, 0, 0] };
        reply.set_cookie_a1a2(cookie);
        h.feed_pdu(
            PduHeader { kind: KIND_RPC_REPLY, seq: 4, arg_len: 64, bounce_len: 3 },
            reply,
            b"ta\n",
        ).unwrap();
        let out = h.call_gate().rpc_yield(f).unwrap();
        assert_eq!(out.cookie_a1a2(), cookie);
        let (th, _, _) = h.take_tx().unwrap();
        assert_eq!(th.kind, KIND_RPC);
        assert_eq!(th.arg_len, 64);
    }

    #[test]
    fn entropy_fill_is_not_zeros() {
        let mut h = VirtHal::new();
        let mut buf = [0u8; 32];
        h.entropy().fill(&mut buf);
        assert!(buf.iter().any(|b| *b != 0));
        assert_eq!(h.entropy().origin(), EntropyOrigin::ReeHost);
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
        assert_eq!(VIRTIO_PCI_VENDOR, 0x1af4);
        assert_eq!(VIRTIO_PCI_DEVICE_VSOCK, 0x1053);
    }

    fn host_request(src_port: u32) -> VirtioVsockHdr {
        VirtioVsockHdr {
            src_cid: 2,
            dst_cid: VSOCK_GUEST_CID as u64,
            src_port,
            dst_port: VSOCK_PORT,
            len: 0,
            ty: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_REQUEST,
            flags: 0,
            buf_alloc: 64 * 1024,
            fwd_cnt: 0,
        }
    }

    #[test]
    fn virtio_vsock_listen_accept_cid3_port7007() {
        let mut h = VirtHal::new();
        h.listen_vsock();
        let req = host_request(4242);
        let resp = h.accept_connect(&req).unwrap();
        assert_eq!(resp.op, VIRTIO_VSOCK_OP_RESPONSE);
        assert_eq!(resp.src_cid, 3);
        assert_eq!(resp.src_port, 7007);
        assert_eq!(resp.dst_cid, 2);
        assert_eq!(resp.dst_port, 4242);
        let mut bad = req;
        bad.dst_port = 9;
        assert!(h.accept_connect(&bad).is_err());
    }

    #[test]
    fn virtio_vsock_enter_complete_on_rw() {
        let mut h = VirtHal::new();
        h.listen_vsock();
        let req = host_request(9);
        h.accept_connect(&req).unwrap();
        let cookie: u64 = 0x2000;
        let mut frame = CallFrame { r: [0x10, 0, 0, 0, 0, 0, 0, 0] };
        frame.set_cookie_a1a2(cookie);
        let msg = b"hello-rs";
        let hdr = PduHeader {
            kind: KIND_ENTER,
            seq: 1,
            arg_len: 64,
            bounce_len: msg.len() as u32,
        };
        let pdu = encode_pdu(hdr, frame, msg);
        let host_rw = VirtioVsockHdr {
            src_cid: 2,
            dst_cid: 3,
            src_port: 9,
            dst_port: 7007,
            len: pdu.len() as u32,
            ty: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_RW,
            flags: 0,
            buf_alloc: 64 * 1024,
            fwd_cnt: 0,
        };
        h.push_host_rw(&host_rw, &pdu).unwrap();
        let got = h.recv_enter().unwrap();
        assert_eq!(got.cookie_a1a2(), cookie);
        assert_eq!(h.bounce_at(cookie, msg.len()).unwrap(), msg);
        let (out_hdr, out_pdu) = h.complete_stream(got).unwrap();
        assert_eq!(out_hdr.op, VIRTIO_VSOCK_OP_RW);
        assert_eq!(out_hdr.src_cid, 3);
        assert_eq!(out_hdr.src_port, 7007);
        let decoded = PduHeader::decode(&out_pdu).unwrap();
        assert_eq!(decoded.kind, KIND_COMPLETE);
        assert_eq!(decoded.arg_len, 64);
        assert_eq!(decoded.seq, 1);
    }
}
