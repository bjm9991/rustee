//! Guest virtio-vsock listen (VIRTIO_ID_VSOCK). Host rustee-virt.ko connects
//! SOCK_STREAM to CID 3 port 7007. Not a virtio-mmio TEE doorbell.
//!
//! Packet layout is the public virtio vsock header (LE). No Linux headers.
#![allow(dead_code)]

use crate::{
    decode_frame, encode_frame, PduHeader, CALL_FRAME_LEN, PDU_HDR_LEN, VSOCK_GUEST_CID, VSOCK_PORT,
};
use alloc::vec::Vec;
use rustee_hal::{CallFrame, HalError};

/// PCI vendor/device for modern virtio vsock (`vhost-vsock-pci`).
pub const VIRTIO_PCI_VENDOR: u16 = 0x1af4;
pub const VIRTIO_PCI_DEVICE_VSOCK: u16 = 0x1053;

pub const VIRTIO_VSOCK_TYPE_STREAM: u16 = 1;
pub const VIRTIO_VSOCK_OP_REQUEST: u16 = 1;
pub const VIRTIO_VSOCK_OP_RESPONSE: u16 = 2;
pub const VIRTIO_VSOCK_OP_RST: u16 = 3;
pub const VIRTIO_VSOCK_OP_SHUTDOWN: u16 = 4;
pub const VIRTIO_VSOCK_OP_RW: u16 = 5;
pub const VIRTIO_VSOCK_OP_CREDIT_UPDATE: u16 = 6;
pub const VIRTIO_VSOCK_OP_CREDIT_REQUEST: u16 = 7;

pub const VIRTIO_VSOCK_HDR_LEN: usize = 44;
pub const VSOCK_BUF_ALLOC: u32 = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioVsockHdr {
    pub src_cid: u64,
    pub dst_cid: u64,
    pub src_port: u32,
    pub dst_port: u32,
    pub len: u32,
    pub ty: u16,
    pub op: u16,
    pub flags: u32,
    pub buf_alloc: u32,
    pub fwd_cnt: u32,
}

impl VirtioVsockHdr {
    pub fn encode(self) -> [u8; VIRTIO_VSOCK_HDR_LEN] {
        let mut b = [0u8; VIRTIO_VSOCK_HDR_LEN];
        b[0..8].copy_from_slice(&self.src_cid.to_le_bytes());
        b[8..16].copy_from_slice(&self.dst_cid.to_le_bytes());
        b[16..20].copy_from_slice(&self.src_port.to_le_bytes());
        b[20..24].copy_from_slice(&self.dst_port.to_le_bytes());
        b[24..28].copy_from_slice(&self.len.to_le_bytes());
        b[28..30].copy_from_slice(&self.ty.to_le_bytes());
        b[30..32].copy_from_slice(&self.op.to_le_bytes());
        b[32..36].copy_from_slice(&self.flags.to_le_bytes());
        b[36..40].copy_from_slice(&self.buf_alloc.to_le_bytes());
        b[40..44].copy_from_slice(&self.fwd_cnt.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self, HalError> {
        if b.len() < VIRTIO_VSOCK_HDR_LEN {
            return Err(HalError::Fault);
        }
        Ok(Self {
            src_cid: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            dst_cid: u64::from_le_bytes(b[8..16].try_into().unwrap()),
            src_port: u32::from_le_bytes(b[16..20].try_into().unwrap()),
            dst_port: u32::from_le_bytes(b[20..24].try_into().unwrap()),
            len: u32::from_le_bytes(b[24..28].try_into().unwrap()),
            ty: u16::from_le_bytes(b[28..30].try_into().unwrap()),
            op: u16::from_le_bytes(b[30..32].try_into().unwrap()),
            flags: u32::from_le_bytes(b[32..36].try_into().unwrap()),
            buf_alloc: u32::from_le_bytes(b[36..40].try_into().unwrap()),
            fwd_cnt: u32::from_le_bytes(b[40..44].try_into().unwrap()),
        })
    }
}

/// Guest listen socket. Bound to CID 3 port 7007 until a host REQUEST arrives.
pub struct VsockListener {
    pub cid: u32,
    pub port: u32,
    listening: bool,
}

impl Default for VsockListener {
    fn default() -> Self {
        Self {
            cid: VSOCK_GUEST_CID,
            port: VSOCK_PORT,
            listening: false,
        }
    }
}

impl VsockListener {
    pub fn listen(&mut self) {
        self.listening = true;
    }

    pub fn is_listening(&self) -> bool {
        self.listening
    }

    /// Answer a host connect REQUEST. Guest is dst (CID 3 port 7007).
    pub fn accept(&self, req: &VirtioVsockHdr) -> Result<VirtioVsockHdr, HalError> {
        if !self.listening {
            return Err(HalError::Busy);
        }
        if req.op != VIRTIO_VSOCK_OP_REQUEST
            || req.ty != VIRTIO_VSOCK_TYPE_STREAM
            || req.dst_cid != self.cid as u64
            || req.dst_port != self.port
        {
            return Err(HalError::InvalidParam);
        }
        Ok(VirtioVsockHdr {
            src_cid: self.cid as u64,
            dst_cid: req.src_cid,
            src_port: self.port,
            dst_port: req.src_port,
            len: 0,
            ty: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_RESPONSE,
            flags: 0,
            buf_alloc: VSOCK_BUF_ALLOC,
            fwd_cnt: 0,
        })
    }
}

/// Accepted SOCK_STREAM. RW ops carry the RUSTEE PDU bytes.
pub struct VsockConn {
    pub guest_cid: u64,
    pub guest_port: u32,
    pub host_cid: u64,
    pub host_port: u32,
    pub fwd_cnt: u32,
    rx: Vec<u8>,
}

impl VsockConn {
    pub fn from_accept(req: &VirtioVsockHdr, listener: &VsockListener) -> Self {
        Self {
            guest_cid: listener.cid as u64,
            guest_port: listener.port,
            host_cid: req.src_cid,
            host_port: req.src_port,
            fwd_cnt: 0,
            rx: Vec::new(),
        }
    }

    pub fn push_rw(&mut self, hdr: &VirtioVsockHdr, payload: &[u8]) -> Result<(), HalError> {
        if hdr.op != VIRTIO_VSOCK_OP_RW
            || hdr.dst_cid != self.guest_cid
            || hdr.dst_port != self.guest_port
            || hdr.src_cid != self.host_cid
            || payload.len() != hdr.len as usize
        {
            return Err(HalError::InvalidParam);
        }
        self.rx.extend_from_slice(payload);
        self.fwd_cnt = self.fwd_cnt.wrapping_add(hdr.len);
        Ok(())
    }

    pub fn recv_exact(&mut self, buf: &mut [u8]) -> Result<(), HalError> {
        if self.rx.len() < buf.len() {
            return Err(HalError::NotFound);
        }
        buf.copy_from_slice(&self.rx[..buf.len()]);
        self.rx.drain(..buf.len());
        Ok(())
    }

    pub fn wrap_rw<'a>(&self, payload: &'a [u8]) -> (VirtioVsockHdr, &'a [u8]) {
        (
            VirtioVsockHdr {
                src_cid: self.guest_cid,
                dst_cid: self.host_cid,
                src_port: self.guest_port,
                dst_port: self.host_port,
                len: payload.len() as u32,
                ty: VIRTIO_VSOCK_TYPE_STREAM,
                op: VIRTIO_VSOCK_OP_RW,
                flags: 0,
                buf_alloc: VSOCK_BUF_ALLOC,
                fwd_cnt: self.fwd_cnt,
            },
            payload,
        )
    }

    /// Host send() credit. Linux updates this from RESPONSE; vhost still
    /// blocks a stream write if peer_buf_alloc stays 0, so send after accept.
    pub fn credit_update(&self) -> VirtioVsockHdr {
        VirtioVsockHdr {
            src_cid: self.guest_cid,
            dst_cid: self.host_cid,
            src_port: self.guest_port,
            dst_port: self.host_port,
            len: 0,
            ty: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_CREDIT_UPDATE,
            flags: 0,
            buf_alloc: VSOCK_BUF_ALLOC,
            fwd_cnt: self.fwd_cnt,
        }
    }
}

/// Read one RUSTEE PDU off an accepted vsock stream.
pub fn read_pdu(conn: &mut VsockConn) -> Result<(PduHeader, CallFrame, Vec<u8>), HalError> {
    let mut hb = [0u8; PDU_HDR_LEN];
    conn.recv_exact(&mut hb)?;
    let hdr = PduHeader::decode(&hb)?;
    if hdr.arg_len != CALL_FRAME_LEN as u32 {
        return Err(HalError::InvalidParam);
    }
    let mut fb = [0u8; CALL_FRAME_LEN];
    conn.recv_exact(&mut fb)?;
    let frame = decode_frame(&fb)?;
    let mut bounce = alloc::vec![0u8; hdr.bounce_len as usize];
    if !bounce.is_empty() {
        conn.recv_exact(&mut bounce)?;
    }
    Ok((hdr, frame, bounce))
}

pub fn encode_pdu(hdr: PduHeader, frame: CallFrame, bounce: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PDU_HDR_LEN + CALL_FRAME_LEN + bounce.len());
    out.extend_from_slice(&hdr.encode());
    out.extend_from_slice(&encode_frame(frame));
    out.extend_from_slice(bounce);
    out
}
