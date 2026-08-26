#![cfg_attr(feature = "boot", no_std)]
#![cfg_attr(feature = "boot", no_main)]

extern crate alloc;

mod heap;
mod mmu;
mod pci;
mod proto_cmd;
mod uart;
mod virtio;

use core::arch::asm;
use core::fmt::Write;
use rustee_crypto::SoftwareProvider;
use rustee_hal::{CallFrame, CallGate, Hal, HalError, Perms};
use rustee_hal_virt::{
    VirtHal, VirtioVsockHdr, VIRTIO_ID_RNG, VIRTIO_PCI_DEVICE_RNG, VIRTIO_PCI_DEVICE_VSOCK,
    VIRTIO_VSOCK_HDR_LEN, VIRTIO_VSOCK_OP_CREDIT_REQUEST, VIRTIO_VSOCK_OP_CREDIT_UPDATE,
    VIRTIO_VSOCK_OP_REQUEST, VIRTIO_VSOCK_OP_RW, VSOCK_GUEST_CID, VSOCK_PORT,
};
use rustee_os::{HalRpc, Kernel, KernelCmd, KernelOut, MemrefSrc, Param, RpcResponse, Uuid};

core::arch::global_asm!(
    r#"
    .section .text.boot
    .global _start
_start:
    mrs x0, cpacr_el1
    orr x0, x0, #(3 << 20)
    msr cpacr_el1, x0
    isb
    ldr x0, =__stack_start
    mov sp, x0
    ldr x0, =__bss_start
    ldr x1, =__bss_end
1:
    cmp x0, x1
    b.ge 2f
    str xzr, [x0], #8
    b 1b
2:
    bl rust_main
3:
    wfe
    b 3b
"#
);

extern "C" {
    static __heap_start: u8;
    static __heap_end: u8;
}

#[no_mangle]
extern "C" fn rust_main() -> ! {
    unsafe { mmu::enable() };
    let heap_start = core::ptr::addr_of!(__heap_start) as usize;
    let heap_end = core::ptr::addr_of!(__heap_end) as usize;
    heap::init(heap_start, heap_end.saturating_sub(heap_start));

    let mut uart = uart::Uart;
    let _ = writeln!(uart, "RUSTEE guest EL1");

    unsafe {
        let rng_dev = pci::find(VIRTIO_PCI_DEVICE_RNG)
            .or_else(|| pci::find(0x1005))
            .unwrap_or_else(|| crate::uart::fail_halt("no virtio-rng-pci"));
        let _ = writeln!(uart, "rng-pci");
        let v = virtio::VirtioPci::probe(&rng_dev)
            .unwrap_or_else(|| crate::uart::fail_halt("virtio-rng probe failed"));
        let _ = writeln!(uart, "rng-probe");
        v.reset_and_ack();
        let _ = writeln!(uart, "rng-features");
        let mut rq = v.setup_queue(0);
        v.driver_ok();
        let _ = writeln!(uart, "rng-driver-ok");
        let mut buf = [0u8; 64];
        virtio::rng_fill(&mut rq, &mut buf);
        let _ = writeln!(uart, "rng-entropy");
        let mut h = VirtHal::new();
        h.feed_rng(&buf);
        let _ = VIRTIO_ID_RNG;
        run(h, uart);
    }
}

fn run(h: VirtHal, mut uart: uart::Uart) -> ! {
    if h.vsock_bound() != Some((VSOCK_GUEST_CID, VSOCK_PORT)) {
        crate::uart::fail_halt("vsock not bound");
    }
    let mut k = Kernel::new(h, SoftwareProvider);
    let _ = writeln!(uart, "kernel");
    let _ = k.emit_ree_notices(&mut uart, Some(VirtHal::boot_notices()));

    unsafe {
        let vs = pci::find(VIRTIO_PCI_DEVICE_VSOCK)
            .unwrap_or_else(|| crate::uart::fail_halt("no vhost-vsock-pci"));
        let _ = writeln!(uart, "vsock-pci");
        let v = virtio::VirtioPci::probe(&vs)
            .unwrap_or_else(|| crate::uart::fail_halt("virtio-vsock probe failed"));
        let _ = writeln!(uart, "vsock-probe");
        v.reset_and_ack();
        let mut rx = v.setup_queue(0);
        let mut tx = v.setup_queue(1);
        let mut ev = v.setup_queue(2);
        v.driver_ok();
        let _ = writeln!(uart, "vsock-driver-ok");
        let mut rxbuf = alloc::vec![0u8; 4096];
        rx.add_in(rxbuf.as_mut_ptr(), 4096, 0);
        let mut evbuf = alloc::vec![0u8; 8];
        ev.add_in(evbuf.as_mut_ptr(), 8, 0);
        let _ = writeln!(uart, "listen {} : {}", VSOCK_GUEST_CID, VSOCK_PORT);
        vsock_loop(&mut k, &mut uart, &mut rx, &mut tx, &mut rxbuf);
    }
}

unsafe fn vsock_loop(
    k: &mut Kernel<VirtHal>,
    uart: &mut uart::Uart,
    rx: &mut virtio::Virtq,
    tx: &mut virtio::Virtq,
    rxbuf: &mut [u8],
) -> ! {
    let mut waiting: Option<CallFrame> = None;
    loop {
        tx.recycle_used();
        let Some((id, len)) = rx.poll_used() else {
            core::hint::spin_loop();
            continue;
        };
        let _ = id;
        if (len as usize) < VIRTIO_VSOCK_HDR_LEN {
            rx.add_in(rxbuf.as_mut_ptr(), 4096, 0);
            continue;
        }
        let hdr = match VirtioVsockHdr::decode(&rxbuf[..VIRTIO_VSOCK_HDR_LEN]) {
            Ok(h) => h,
            Err(_) => {
                rx.add_in(rxbuf.as_mut_ptr(), 4096, 0);
                continue;
            }
        };
        let payload = &rxbuf[VIRTIO_VSOCK_HDR_LEN..len as usize];
        match hdr.op {
            VIRTIO_VSOCK_OP_REQUEST => {
                match k.hal_mut().accept_connect(&hdr) {
                    Ok(resp) => {
                        tx.add_out_owned(resp.encode().to_vec());
                        let _ = writeln!(uart, "vsock accept {}:{}", hdr.src_cid, hdr.src_port);
                        if let Ok(cu) = k.hal_mut().credit_update() {
                            tx.add_out_owned(cu.encode().to_vec());
                        }
                    }
                    Err(_) => crate::uart::fail_halt("vsock REQUEST reject"),
                }
            }
            VIRTIO_VSOCK_OP_RW => {
                let _ = writeln!(uart, "vsock-rw {}", hdr.len);
                if k.hal_mut().push_host_rw(&hdr, payload).is_ok() {
                    if waiting.is_some() {
                        match k.hal_mut().recv_rpc_reply() {
                            Ok(_) => {
                                let enter = waiting.take().unwrap();
                                handle_rpc_reply(k, uart, tx, enter, &mut waiting);
                            }
                            Err(HalError::NotFound) => {}
                            Err(_) => crate::uart::fail_halt("rpc reply"),
                        }
                    } else {
                        match k.hal_mut().recv_enter() {
                            Ok(frame) => {
                                let _ = writeln!(uart, "vsock-enter");
                                handle_enter(k, uart, tx, frame, &mut waiting);
                            }
                            Err(HalError::NotFound) => {}
                            Err(_) => {
                                let _ = writeln!(uart, "vsock-enter-drop");
                            }
                        }
                    }
                    if let Ok(cu) = k.hal_mut().credit_update() {
                        tx.add_out_owned(cu.encode().to_vec());
                    }
                } else {
                    let _ = writeln!(uart, "vsock-rw-drop");
                }
            }
            VIRTIO_VSOCK_OP_CREDIT_REQUEST => {
                if let Ok(cu) = k.hal_mut().credit_update() {
                    tx.add_out_owned(cu.encode().to_vec());
                }
            }
            VIRTIO_VSOCK_OP_CREDIT_UPDATE => {}
            op => {
                let _ = writeln!(uart, "vsock-op {}", op);
            }
        }
        rx.add_in(rxbuf.as_mut_ptr(), 4096, 0);
    }
}

fn handle_enter(
    k: &mut Kernel<VirtHal>,
    uart: &mut uart::Uart,
    tx: &mut virtio::Virtq,
    frame: CallFrame,
    waiting: &mut Option<CallFrame>,
) {
    let cookie = frame.cookie_a1a2();
    let cmd = {
        let Some(pool) = k.hal_mut().bounce_at(0, rustee_hal_virt::BOUNCE_POOL_SIZE) else {
            crate::uart::fail_halt("bounce");
        };
        match proto_cmd::decode_cmd(pool, cookie) {
            Ok(c) => c,
            Err(_) => {
                let _ = writeln!(uart, "vsock-cmd-bad");
                if let Some(buf) = k
                    .hal_mut()
                    .bounce_at_mut(0, rustee_hal_virt::BOUNCE_POOL_SIZE)
                {
                    proto_cmd::write_done(buf, cookie, 0xFFFF_0006, 4, 0);
                }
                if let Ok((vh, pdu)) = k.hal_mut().complete_stream(frame) {
                    send_rw(tx, vh, &pdu);
                }
                return;
            }
        }
    };
    import_memrefs(k, &cmd);
    let out = k.handle(cmd);
    dispatch_out(k, uart, tx, frame, out, waiting);
}

fn handle_rpc_reply(
    k: &mut Kernel<VirtHal>,
    uart: &mut uart::Uart,
    tx: &mut virtio::Virtq,
    enter: CallFrame,
    waiting: &mut Option<CallFrame>,
) {
    let resp = {
        let Some(pool) = k.hal_mut().bounce_at(0, rustee_hal_virt::BOUNCE_POOL_SIZE) else {
            crate::uart::fail_halt("bounce");
        };
        match proto_cmd::take_load_ta(pool) {
            Ok(bytes) => RpcResponse::LoadTa { bytes },
            Err(code) => RpcResponse::Error { code },
        }
    };
    let out = k.handle(KernelCmd::RpcComplete { resp });
    dispatch_out(k, uart, tx, enter, out, waiting);
}

fn dispatch_out(
    k: &mut Kernel<VirtHal>,
    uart: &mut uart::Uart,
    tx: &mut virtio::Virtq,
    frame: CallFrame,
    out: KernelOut,
    waiting: &mut Option<CallFrame>,
) {
    match out {
        KernelOut::Done {
            result, session, ..
        } => {
            let cookie = frame.cookie_a1a2();
            if let Some(buf) = k
                .hal_mut()
                .bounce_at_mut(0, rustee_hal_virt::BOUNCE_POOL_SIZE)
            {
                proto_cmd::write_done(
                    buf,
                    cookie,
                    result.code,
                    result.origin.as_gp(),
                    session.map(|s| s.0).unwrap_or(0),
                );
            }
            if let Ok((vh, pdu)) = k.hal_mut().complete_stream(frame) {
                send_rw(tx, vh, &pdu);
                let _ = writeln!(uart, "vsock-complete");
            } else {
                let _ = writeln!(uart, "vsock-complete-drop");
            }
        }
        KernelOut::Rpc(HalRpc::LoadTa { uuid }) => {
            let _ = writeln!(uart, "vsock-rpc");
            send_load_ta(k, tx, uuid);
            *waiting = Some(frame);
        }
        KernelOut::Rpc(_) => crate::uart::fail_halt("rpc not LoadTa"),
    }
}

fn send_load_ta(k: &mut Kernel<VirtHal>, tx: &mut virtio::Virtq, uuid: Uuid) {
    let (cookie, bounce_len) = {
        let Some(buf) = k
            .hal_mut()
            .bounce_at_mut(0, rustee_hal_virt::BOUNCE_POOL_SIZE)
        else {
            crate::uart::fail_halt("bounce");
        };
        proto_cmd::pack_load_ta(buf, uuid)
            .unwrap_or_else(|_| crate::uart::fail_halt("pack LOAD_TA"))
    };
    k.hal_mut().set_rpc_window(cookie, bounce_len);
    let mut rpc_frame = CallFrame { r: [0; 8] };
    rpc_frame.set_cookie_a1a2(cookie);
    let _ = k.hal_mut().call_gate().rpc_yield(rpc_frame);
    let Some((hdr, fr, bounce)) = k.hal_mut().take_tx() else {
        crate::uart::fail_halt("rpc tx");
    };
    let pdu = rustee_hal_virt::encode_pdu(hdr, fr, &bounce);
    if let Ok(vh) = k.hal_mut().wrap_outgoing(&pdu) {
        send_rw(tx, vh, &pdu);
    }
}

fn send_rw(tx: &mut virtio::Virtq, vh: rustee_hal_virt::VirtioVsockHdr, pdu: &[u8]) {
    let mut pkt = vh.encode().to_vec();
    pkt.extend_from_slice(pdu);
    unsafe { tx.add_out_owned(pkt) };
}

fn import_memrefs(k: &mut Kernel<VirtHal>, cmd: &rustee_os::KernelCmd) {
    let params: &[Param; 4] = match cmd {
        rustee_os::KernelCmd::OpenSession { params, .. }
        | rustee_os::KernelCmd::Invoke { params, .. } => params,
        _ => return,
    };
    for p in params {
        if let Param::Memref {
            src: MemrefSrc::Ree { cookie, offs },
            size,
            dir,
        } = *p
        {
            let perms = match dir {
                rustee_os::Dir::In => Perms::READ,
                rustee_os::Dir::Out => Perms::WRITE,
                rustee_os::Dir::InOut => Perms::RW,
            };
            let start = cookie + offs as u64;
            let len = size.max(1);
            let _ = k.hal_mut().import_shm(start, len, perms);
        }
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let mut uart = uart::Uart;
    let _ = writeln!(uart, "panic: {info}");
    loop {
        unsafe { asm!("wfe") }
    }
}
