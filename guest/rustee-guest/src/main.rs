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
use rustee_hal::{CallGate, Hal, Perms};
use rustee_hal_virt::{
    VirtHal, VirtioVsockHdr, VIRTIO_ID_RNG, VIRTIO_PCI_DEVICE_RNG, VIRTIO_PCI_DEVICE_VSOCK,
    VIRTIO_VSOCK_HDR_LEN, VIRTIO_VSOCK_OP_REQUEST, VIRTIO_VSOCK_OP_RW, VSOCK_GUEST_CID, VSOCK_PORT,
};
use rustee_os::{Kernel, KernelOut, MemrefSrc, Param};

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

#[no_mangle]
extern "C" fn rust_main() -> ! {
    unsafe { mmu::enable() };
    let heap_start = 0x4200_0000usize;
    heap::init(heap_start, 64 * 1024 * 1024);

    let mut uart = uart::Uart;
    let _ = writeln!(uart, "RUSTEE guest EL1");

    unsafe {
        if let Some(rng_dev) = pci::find(VIRTIO_PCI_DEVICE_RNG).or_else(|| pci::find(0x1005)) {
            if let Some(v) = virtio::VirtioPci::probe(&rng_dev) {
                v.reset_and_ack();
                let mut buf = [0u8; 64];
                virtio::rng_fill(&v, &mut buf);
                v.driver_ok();
                let mut h = VirtHal::new();
                h.feed_rng(&buf);
                let _ = VIRTIO_ID_RNG;
                run(h, uart);
            }
        }
    }

    // Still boot HAL (listen + rng emulator) if virtio-rng BAR is missing.
    let h = VirtHal::new();
    run(h, uart);
}

fn run(h: VirtHal, mut uart: uart::Uart) -> ! {
    if h.vsock_bound() != Some((VSOCK_GUEST_CID, VSOCK_PORT)) {
        let _ = writeln!(uart, "vsock not bound");
        loop { unsafe { asm!("wfe") } }
    }
    let mut k = Kernel::new(h, SoftwareProvider);
    let _ = k.emit_ree_notices(&mut uart, Some(VirtHal::boot_notices()));
    let _ = writeln!(uart, "listen {} : {}", VSOCK_GUEST_CID, VSOCK_PORT);

    unsafe {
        if let Some(vs) = pci::find(VIRTIO_PCI_DEVICE_VSOCK) {
            if let Some(v) = virtio::VirtioPci::probe(&vs) {
                v.reset_and_ack();
                let mut rx = v.setup_queue(0);
                let mut tx = v.setup_queue(1);
                let _ev = v.setup_queue(2);
                v.driver_ok();
                let mut rxbuf = alloc::vec![0u8; 4096];
                rx.add_in(rxbuf.as_mut_ptr(), 4096, 0);
                vsock_loop(&mut k, &mut uart, &mut rx, &mut tx, &mut rxbuf);
            }
        }
    }
    let _ = writeln!(uart, "no vhost-vsock-pci");
    loop { unsafe { asm!("wfe") } }
}

unsafe fn vsock_loop(
    k: &mut Kernel<VirtHal>,
    uart: &mut uart::Uart,
    rx: &mut virtio::Virtq,
    tx: &mut virtio::Virtq,
    rxbuf: &mut [u8],
) -> ! {
    let mut txid = 1u16;
    loop {
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
                if let Ok(resp) = k.hal_mut().accept_connect(&hdr) {
                    let b = resp.encode();
                    tx.add_out(b.as_ptr(), b.len() as u32, txid);
                    txid = txid.wrapping_add(1);
                    let _ = writeln!(uart, "vsock accept {}:{}", hdr.src_cid, hdr.src_port);
                }
            }
            VIRTIO_VSOCK_OP_RW => {
                if k.hal_mut().push_host_rw(&hdr, payload).is_ok() {
                    if let Ok(frame) = k.hal_mut().recv_enter() {
                        handle_enter(k, uart, tx, &mut txid, frame);
                    }
                }
            }
            _ => {}
        }
        rx.add_in(rxbuf.as_mut_ptr(), 4096, 0);
    }
}

fn handle_enter(
    k: &mut Kernel<VirtHal>,
    uart: &mut uart::Uart,
    tx: &mut virtio::Virtq,
    txid: &mut u16,
    frame: rustee_hal::CallFrame,
) {
    let cookie = frame.cookie_a1a2();
    let poolv = k
        .hal_mut()
        .bounce_at(0, rustee_hal_virt::BOUNCE_POOL_SIZE)
        .map(|p| p.to_vec());
    let Some(poolv) = poolv else { return };
    let Ok(cmd) = proto_cmd::decode_cmd(&poolv, cookie) else { return };
    import_memrefs(k, &cmd);
    match k.handle(cmd) {
        KernelOut::Done { result, session, .. } => {
            if let Some(buf) = k.hal_mut().bounce_at_mut(0, rustee_hal_virt::BOUNCE_POOL_SIZE) {
                proto_cmd::write_done(
                    buf,
                    cookie,
                    result.code,
                    result.origin.as_gp(),
                    session.map(|s| s.0).unwrap_or(0),
                );
            }
            if let Ok((vh, pdu)) = k.hal_mut().complete_stream(frame) {
                send_rw(tx, txid, vh, &pdu);
            }
            let _ = uart;
        }
        KernelOut::Rpc(_) => {
            let _ = k.hal_mut().call_gate().rpc_yield(frame);
            if let Some((hdr, fr, bounce)) = k.hal_mut().take_tx() {
                let pdu = rustee_hal_virt::encode_pdu(hdr, fr, &bounce);
                if let Ok(vh) = k.hal_mut().wrap_outgoing(&pdu) {
                    send_rw(tx, txid, vh, &pdu);
                }
            }
        }
    }
}

fn send_rw(tx: &mut virtio::Virtq, txid: &mut u16, vh: rustee_hal_virt::VirtioVsockHdr, pdu: &[u8]) {
    let mut pkt = vh.encode().to_vec();
    pkt.extend_from_slice(pdu);
    let len = pkt.len() as u32;
    let ptr = pkt.as_ptr();
    unsafe { tx.add_out(ptr, len, *txid) };
    *txid = txid.wrapping_add(1);
    core::mem::forget(pkt);
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
    loop { unsafe { asm!("wfe") } }
}
