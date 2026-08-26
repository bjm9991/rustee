//! Live vsock PDU IO. arg is always 64-byte CallFrame. MSG stays in bounce.
use std::io::{Read, Write};

use rustee_proto::{
    decode_msg, write_msg, CallFrame, PduHeader, CALL_FRAME_LEN, KIND_COMPLETE, KIND_ENTER,
    KIND_RPC, KIND_RPC_REPLY, PDU_HDR_LEN, VSOCK_GUEST_CID, VSOCK_PORT,
};

use crate::{TEEC_ERROR_BUSY, TEEC_ERROR_COMMUNICATION};

pub const GUEST_CID: u32 = VSOCK_GUEST_CID;
pub const GUEST_PORT: u32 = VSOCK_PORT;

/// One outstanding yielding call over a byte stream (AF_VSOCK or a test pipe).
pub struct StreamTransport<S> {
    sock: S,
    seq: u32,
    yielding: bool,
    /// Optional RPC: mutate bounce at the MSG cookie, then we send RPC_REPLY.
    /// `Ok(n)` with n>0 is the RPC_REPLY bounce_len (covers ELF after LOAD_TA).
    /// `Ok(0)` keeps the RPC PDU bounce_len.
    pub on_rpc: Option<fn(&mut [u8], u64) -> Result<u32, u32>>,
}

impl<S> StreamTransport<S> {
    pub fn new(sock: S) -> Self {
        Self {
            sock,
            seq: 1,
            yielding: false,
            on_rpc: None,
        }
    }
}

fn write_all(w: &mut impl Write, buf: &[u8]) -> Result<(), u32> {
    w.write_all(buf).map_err(|_| TEEC_ERROR_COMMUNICATION)
}

fn read_exact(r: &mut impl Read, buf: &mut [u8]) -> Result<(), u32> {
    r.read_exact(buf).map_err(|_| TEEC_ERROR_COMMUNICATION)
}

pub fn write_pdu(
    w: &mut impl Write,
    kind: u32,
    seq: u32,
    frame: CallFrame,
    bounce: &[u8],
    bounce_len: u32,
) -> Result<(), u32> {
    let hdr = PduHeader::yielding(kind, seq, bounce_len);
    write_all(w, &hdr.encode())?;
    write_all(w, &frame.encode())?;
    let c = frame.cookie() as usize;
    let n = bounce_len as usize;
    if c.checked_add(n).map(|e| e > bounce.len()).unwrap_or(true) {
        return Err(TEEC_ERROR_COMMUNICATION);
    }
    write_all(w, &bounce[c..c + n])?;
    Ok(())
}

pub fn read_pdu(r: &mut impl Read, bounce: &mut [u8]) -> Result<(PduHeader, CallFrame), u32> {
    let mut hb = [0u8; PDU_HDR_LEN];
    read_exact(r, &mut hb)?;
    let hdr = PduHeader::decode(&hb).map_err(|_| TEEC_ERROR_COMMUNICATION)?;
    let mut fb = [0u8; CALL_FRAME_LEN];
    read_exact(r, &mut fb)?;
    let frame = CallFrame::decode(&fb).map_err(|_| TEEC_ERROR_COMMUNICATION)?;
    let c = frame.cookie() as usize;
    let n = hdr.bounce_len as usize;
    if c.checked_add(n).map(|e| e > bounce.len()).unwrap_or(true) {
        return Err(TEEC_ERROR_COMMUNICATION);
    }
    if n > 0 {
        read_exact(r, &mut bounce[c..c + n])?;
    }
    Ok((hdr, frame))
}

/// Guest is parked on ENTER until RPC_REPLY. `hdr.ret == 0` is success; never omit the reply.
fn stamp_rpc_ret(bounce: &mut [u8], cookie: u64, ret: u32) {
    let ret = if ret == 0 { TEEC_ERROR_COMMUNICATION } else { ret };
    if let Ok((mut hdr, params, _)) = decode_msg(bounce, cookie) {
        hdr.ret = ret;
        let n = hdr.num_params as usize;
        let _ = write_msg(bounce, cookie, hdr, &params[..n]);
    }
}

impl<S: Read + Write> crate::Transport for StreamTransport<S> {
    fn enter(
        &mut self,
        frame: CallFrame,
        bounce: &mut [u8],
        bounce_len: u32,
    ) -> Result<CallFrame, u32> {
        if self.yielding {
            return Err(TEEC_ERROR_BUSY);
        }
        self.yielding = true;
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        write_pdu(&mut self.sock, KIND_ENTER, seq, frame, bounce, bounce_len)?;
        loop {
            let (hdr, out) = read_pdu(&mut self.sock, bounce)?;
            match hdr.kind {
                KIND_COMPLETE => {
                    self.yielding = false;
                    return Ok(out);
                }
                KIND_RPC => {
                    let mut reply_len = hdr.bounce_len;
                    if let Some(h) = self.on_rpc {
                        match h(bounce, out.cookie()) {
                            Ok(n) if n > 0 => reply_len = n,
                            Ok(_) => {}
                            Err(code) => stamp_rpc_ret(bounce, out.cookie(), code),
                        }
                    }
                    write_pdu(
                        &mut self.sock,
                        KIND_RPC_REPLY,
                        hdr.seq,
                        rustee_proto::CallFrame::return_from_rpc(out.cookie()),
                        bounce,
                        reply_len,
                    )?;
                }
                KIND_ENTER | KIND_RPC_REPLY => {
                    self.yielding = false;
                    return Err(TEEC_ERROR_COMMUNICATION);
                }
                _ => {
                    self.yielding = false;
                    return Err(TEEC_ERROR_COMMUNICATION);
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub fn connect_vsock(cid: u32, port: u32) -> Result<std::os::fd::OwnedFd, u32> {
    use std::mem::MaybeUninit;
    use std::os::fd::{FromRawFd, OwnedFd};
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(TEEC_ERROR_COMMUNICATION);
        }
        let mut addr = MaybeUninit::<libc::sockaddr_vm>::zeroed().assume_init();
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_port = port;
        addr.svm_cid = cid;
        let rc = libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            core::mem::size_of::<libc::sockaddr_vm>() as u32,
        );
        if rc != 0 {
            libc::close(fd);
            return Err(TEEC_ERROR_COMMUNICATION);
        }
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

#[cfg(target_os = "linux")]
pub fn vsock_transport(cid: u32, port: u32) -> Result<StreamTransport<std::fs::File>, u32> {
    let fd = connect_vsock(cid, port)?;
    Ok(StreamTransport::new(std::fs::File::from(fd)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Transport;
    use rustee_proto::{KIND_COMPLETE, KIND_RPC, SMC_CALL_WITH_ARG};
    use std::os::unix::net::UnixStream;

    #[test]
    fn unix_pair_enter_complete_copies_bounce() {
        let (mut server, client) = UnixStream::pair().unwrap();
        let mut host = StreamTransport::new(client);
        std::thread::spawn(move || {
            let mut bounce = vec![0u8; 256];
            let (hdr, frame) = read_pdu(&mut server, &mut bounce).unwrap();
            assert_eq!(hdr.kind, KIND_ENTER);
            assert_eq!(hdr.arg_len, 64);
            assert_eq!(frame.r[0] as u32, SMC_CALL_WITH_ARG);
            bounce[8] = 0xAB;
            write_pdu(
                &mut server,
                KIND_COMPLETE,
                hdr.seq,
                frame,
                &bounce,
                hdr.bounce_len,
            )
            .unwrap();
        });
        let mut bounce = vec![0u8; 256];
        bounce[8] = 0x11;
        let mut frame = CallFrame::default();
        frame.r[0] = SMC_CALL_WITH_ARG as u64;
        frame.set_cookie(8);
        let out = host.enter(frame, &mut bounce, 16).unwrap();
        assert_eq!(bounce[8], 0xAB);
        assert_eq!(out.cookie(), 8);
    }

    fn mark_rpc(b: &mut [u8], c: u64) -> Result<u32, u32> {
        b[c as usize + 1] = 0xCD;
        Ok(0)
    }

    #[test]
    fn unix_pair_rpc_then_complete() {
        let (mut server, client) = UnixStream::pair().unwrap();
        let mut host = StreamTransport::new(client);
        host.on_rpc = Some(mark_rpc);
        std::thread::spawn(move || {
            let mut bounce = vec![0u8; 256];
            let (hdr, frame) = read_pdu(&mut server, &mut bounce).unwrap();
            assert_eq!(hdr.kind, KIND_ENTER);
            bounce[8] = 0x22;
            write_pdu(
                &mut server,
                KIND_RPC,
                hdr.seq,
                frame,
                &bounce,
                hdr.bounce_len,
            )
            .unwrap();
            let (rh, _) = read_pdu(&mut server, &mut bounce).unwrap();
            assert_eq!(rh.kind, KIND_RPC_REPLY);
            assert_eq!(bounce[9], 0xCD);
            bounce[8] = 0xAB;
            write_pdu(
                &mut server,
                KIND_COMPLETE,
                hdr.seq,
                frame,
                &bounce,
                hdr.bounce_len,
            )
            .unwrap();
        });
        let mut bounce = vec![0u8; 256];
        let mut frame = CallFrame::default();
        frame.r[0] = SMC_CALL_WITH_ARG as u64;
        frame.set_cookie(8);
        let _ = host.enter(frame, &mut bounce, 16).unwrap();
        assert_eq!(bounce[8], 0xAB);
    }

    #[test]
    fn second_enter_while_yielding_is_busy() {
        let (server, client) = UnixStream::pair().unwrap();
        let mut host = StreamTransport::new(client);
        host.yielding = true;
        let _ = server;
        let mut bounce = vec![0u8; 16];
        let err = host
            .enter(CallFrame::default(), &mut bounce, 16)
            .unwrap_err();
        assert_eq!(err, TEEC_ERROR_BUSY);
    }

    fn fail_rpc(_b: &mut [u8], _c: u64) -> Result<u32, u32> {
        Err(0xFFFF_0008)
    }

    #[test]
    fn rpc_error_still_sends_reply() {
        use rustee_proto::{write_msg, MsgArgHdr, MsgParam, RPC_CMD_LOAD_TA};
        let (mut server, client) = UnixStream::pair().unwrap();
        let mut host = StreamTransport::new(client);
        host.on_rpc = Some(fail_rpc);
        std::thread::spawn(move || {
            let mut bounce = vec![0u8; 256];
            let (hdr, frame) = read_pdu(&mut server, &mut bounce).unwrap();
            assert_eq!(hdr.kind, KIND_ENTER);
            let cookie = frame.cookie();
            let msg = MsgArgHdr {
                cmd: RPC_CMD_LOAD_TA,
                num_params: 1,
                ..MsgArgHdr::default()
            };
            write_msg(&mut bounce, cookie, msg, &[MsgParam::default()]).unwrap();
            write_pdu(
                &mut server,
                KIND_RPC,
                hdr.seq,
                frame,
                &bounce,
                hdr.bounce_len,
            )
            .unwrap();
            let (rh, _) = read_pdu(&mut server, &mut bounce).unwrap();
            assert_eq!(rh.kind, KIND_RPC_REPLY);
            let (out, _, _) = rustee_proto::decode_msg(&bounce, cookie).unwrap();
            assert_eq!(out.ret, 0xFFFF_0008);
            write_pdu(
                &mut server,
                KIND_COMPLETE,
                hdr.seq,
                frame,
                &bounce,
                hdr.bounce_len,
            )
            .unwrap();
        });
        let mut bounce = vec![0u8; 256];
        let mut frame = CallFrame::default();
        frame.r[0] = SMC_CALL_WITH_ARG as u64;
        frame.set_cookie(64);
        let _ = host.enter(frame, &mut bounce, 96).unwrap();
    }
}
