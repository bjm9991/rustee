//! Minimal virtio-pci modern (common cfg + notify + one split queue).
use crate::pci::{self, PciDev};
use alloc::vec::Vec;

const CAP_COMMON: u8 = 1;
const CAP_NOTIFY: u8 = 2;
const CAP_ISR: u8 = 3;
const CAP_DEVICE: u8 = 4;

const S_ACK: u8 = 1;
const S_DRIVER: u8 = 2;
const S_DRIVER_OK: u8 = 4;
const S_FEATURES_OK: u8 = 8;

const QSIZE: usize = 16;

#[repr(C)]
struct SplitQ {
    desc: [Desc; QSIZE],
    avail_flags: u16,
    avail_idx: u16,
    avail_ring: [u16; QSIZE],
    used_pad: [u8; 4],
    used_flags: u16,
    used_idx: u16,
    used_ring: [UsedElem; QSIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UsedElem {
    id: u32,
    len: u32,
}

pub struct Virtq {
    q: *mut SplitQ,
    last_used: u16,
    notify: *mut u16,
    /// TX packet buffers. Slot `i` is live while desc `i` is in flight.
    bufs: [Option<Vec<u8>>; QSIZE],
    inflight: [bool; QSIZE],
}

pub struct VirtioPci {
    pub common: *mut u8,
    pub notify: *mut u8,
    pub device: *mut u8,
    notify_off_mul: u32,
}

unsafe fn cap_at(d: &PciDev, off: u8) -> (u8, u8, u8, u32, u32) {
    // type, bar, next, offset, length
    let t = pci::cfg_read8(d.bus, d.dev, d.func, off as u16 + 3);
    let bar = pci::cfg_read8(d.bus, d.dev, d.func, off as u16 + 4);
    let next = pci::cfg_read8(d.bus, d.dev, d.func, off as u16 + 1);
    let cap_off = pci::cfg_read32(d.bus, d.dev, d.func, off as u16 + 8);
    let len = pci::cfg_read32(d.bus, d.dev, d.func, off as u16 + 12);
    (t, bar, next, cap_off, len)
}

impl VirtioPci {
    pub unsafe fn probe(d: &PciDev) -> Option<Self> {
        let status = pci::cfg_read8(d.bus, d.dev, d.func, 0x06) as u16; // actually command+status
        let _ = status;
        let mut cap = pci::cfg_read8(d.bus, d.dev, d.func, 0x34);
        let mut common = 0u64;
        let mut notify = 0u64;
        let mut device = 0u64;
        let mut notify_mul = 0u32;
        let mut seen = 0;
        while cap != 0 && seen < 16 {
            seen += 1;
            let id = pci::cfg_read8(d.bus, d.dev, d.func, cap as u16);
            let next = pci::cfg_read8(d.bus, d.dev, d.func, cap as u16 + 1);
            if id == 0x09 {
                let (t, bar, _, off, _) = cap_at(d, cap);
                // COMMON/NOTIFY/ISR/DEVICE only. PCI_CFG (type 5) often names
                // BAR0, which is legacy I/O on QEMU virtio-pci — skip, do not map.
                match t {
                    CAP_COMMON | CAP_NOTIFY | CAP_ISR | CAP_DEVICE => {
                        let Some(base) = pci::map_bar(d, bar) else {
                            cap = next;
                            continue;
                        };
                        let addr = base + off as u64;
                        match t {
                            CAP_COMMON => common = addr,
                            CAP_NOTIFY => {
                                notify = addr;
                                notify_mul =
                                    pci::cfg_read32(d.bus, d.dev, d.func, cap as u16 + 16);
                            }
                            CAP_DEVICE => device = addr,
                            CAP_ISR => {}
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            cap = next;
        }
        if common == 0 {
            return None;
        }
        Some(Self {
            common: common as *mut u8,
            notify: notify as *mut u8,
            device: device as *mut u8,
            notify_off_mul: notify_mul,
        })
    }

    unsafe fn w8(&self, off: usize, v: u8) {
        core::ptr::write_volatile(self.common.add(off), v);
    }
    unsafe fn r8(&self, off: usize) -> u8 {
        core::ptr::read_volatile(self.common.add(off))
    }
    unsafe fn w16(&self, off: usize, v: u16) {
        core::ptr::write_volatile(self.common.add(off) as *mut u16, v);
    }
    unsafe fn r16(&self, off: usize) -> u16 {
        core::ptr::read_volatile(self.common.add(off) as *mut u16)
    }
    unsafe fn w32(&self, off: usize, v: u32) {
        core::ptr::write_volatile(self.common.add(off) as *mut u32, v);
    }
    unsafe fn w64(&self, off: usize, v: u64) {
        core::ptr::write_volatile(self.common.add(off) as *mut u64, v);
    }

    pub unsafe fn reset_and_ack(&self) {
        self.w8(20, 0); // device_status
                        // common cfg layout (virtio 1.2):
                        // 0 device_feature_select u32
                        // 4 device_feature u32
                        // 8 driver_feature_select u32
                        // 12 driver_feature u32
                        // 16 msix_config u16
                        // 18 num_queues u16
                        // 20 device_status u8
                        // 21 config_generation u8
        self.w8(20, S_ACK | S_DRIVER);
        // Low 32 feature bits: none.
        self.w32(8, 0);
        self.w32(12, 0);
        // VIRTIO_F_VERSION_1 is feature bit 32 → word 1, bit 0.
        self.w32(8, 1);
        self.w32(12, 1);
        self.w8(20, S_ACK | S_DRIVER | S_FEATURES_OK);
        let st = self.r8(20);
        if st & S_FEATURES_OK == 0 {
            crate::uart::fail_halt("virtio FEATURES_OK not sticky (need VIRTIO_F_VERSION_1)");
        }
    }

    pub unsafe fn setup_queue(&self, idx: u16) -> Virtq {
        self.w16(22, idx); // queue_select
        let size = QSIZE as u16;
        self.w16(24, size); // queue_size
        self.w16(26, 0xffff); // no msix
        let layout =
            core::alloc::Layout::from_size_align(core::mem::size_of::<SplitQ>(), 16).unwrap();
        let q = alloc::alloc::alloc_zeroed(layout) as *mut SplitQ;
        let pa = q as u64;
        // SplitQ layout: desc 16*16=256, avail_flags+idx=4, ring 32, pad 4, used_flags+idx=4, used 16*8=128
        let avail_off = core::mem::offset_of!(SplitQ, avail_flags) as u64;
        let used_off = core::mem::offset_of!(SplitQ, used_flags) as u64;
        self.w64(32, pa);
        self.w64(40, pa + avail_off);
        self.w64(48, pa + used_off);
        self.w16(28, 1); // queue_enable
        let n_off = self.r16(30) as u32; // queue_notify_off
        if self.notify.is_null() {
            crate::uart::fail_halt("virtio notify BAR missing");
        }
        let notify = self.notify.add((n_off * self.notify_off_mul) as usize) as *mut u16;
        const NONE: Option<Vec<u8>> = None;
        Virtq {
            q,
            last_used: 0,
            notify,
            bufs: [NONE; QSIZE],
            inflight: [false; QSIZE],
        }
    }

    pub unsafe fn driver_ok(&self) {
        self.w8(20, S_ACK | S_DRIVER | S_FEATURES_OK | S_DRIVER_OK);
    }
}

impl Virtq {
    fn cap_id(id: u16) -> u16 {
        id % (QSIZE as u16)
    }

    /// Recycle every TX used descriptor. Must be polled so ids 0..16 can be reused.
    pub unsafe fn recycle_used(&mut self) {
        while self.poll_used().is_some() {}
    }

    fn alloc_desc(&mut self) -> Option<u16> {
        unsafe { self.recycle_used() };
        for i in 0..QSIZE {
            if !self.inflight[i] {
                return Some(i as u16);
            }
        }
        None
    }

    /// Own `pkt` in a desc slot until the device writes used. No `mem::forget`.
    pub unsafe fn add_out_owned(&mut self, pkt: Vec<u8>) {
        let id = loop {
            if let Some(id) = self.alloc_desc() {
                break id;
            }
            core::hint::spin_loop();
        };
        self.bufs[id as usize] = Some(pkt);
        self.inflight[id as usize] = true;
        let (ptr, len) = {
            let buf = self.bufs[id as usize].as_ref().unwrap();
            (buf.as_ptr(), buf.len() as u32)
        };
        self.add_out(ptr, len, id);
    }

    pub unsafe fn add_in(&mut self, buf: *mut u8, len: u32, id: u16) {
        let id = Self::cap_id(id);
        self.inflight[id as usize] = true;
        let q = &mut *self.q;
        q.desc[id as usize] = Desc {
            addr: buf as u64,
            len,
            flags: 2, // WRITE (device writes)
            next: 0,
        };
        let idx = q.avail_idx;
        q.avail_ring[(idx as usize) % QSIZE] = id;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        q.avail_idx = idx.wrapping_add(1);
        core::ptr::write_volatile(self.notify, 0);
    }

    pub unsafe fn add_out(&mut self, buf: *const u8, len: u32, id: u16) {
        let id = Self::cap_id(id);
        let q = &mut *self.q;
        q.desc[id as usize] = Desc {
            addr: buf as u64,
            len,
            flags: 0,
            next: 0,
        };
        let idx = q.avail_idx;
        q.avail_ring[(idx as usize) % QSIZE] = id;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        q.avail_idx = idx.wrapping_add(1);
        core::ptr::write_volatile(self.notify, 0);
    }

    pub unsafe fn poll_used(&mut self) -> Option<(u16, u32)> {
        let q = &*self.q;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        if q.used_idx == self.last_used {
            return None;
        }
        let e = q.used_ring[(self.last_used as usize) % QSIZE];
        self.last_used = self.last_used.wrapping_add(1);
        let id = (e.id as u16) % (QSIZE as u16);
        self.inflight[id as usize] = false;
        // Keep bufs[id] allocated for reuse; drop only when replaced in add_out_owned.
        Some((id, e.len))
    }
}

pub unsafe fn rng_fill(dev: &VirtioPci, buf: &mut [u8]) {
    let mut q = dev.setup_queue(0);
    q.add_in(buf.as_mut_ptr(), buf.len() as u32, 0);
    for _ in 0..1_000_000 {
        if q.poll_used().is_some() {
            return;
        }
        core::hint::spin_loop();
    }
    crate::uart::fail_halt("virtio-rng timeout");
}
