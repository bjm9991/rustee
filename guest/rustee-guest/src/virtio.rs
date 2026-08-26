//! Minimal virtio-pci modern (common cfg + notify + one split queue).
use crate::pci::{self, PciDev};

const CAP_COMMON: u8 = 1;
const CAP_NOTIFY: u8 = 2;
const CAP_ISR: u8 = 3;
const CAP_DEVICE: u8 = 4;

const S_ACK: u8 = 1;
const S_DRIVER: u8 = 2;
const S_DRIVER_OK: u8 = 4;
const S_FEATURES_OK: u8 = 8;

#[repr(C)]
struct SplitQ {
    desc: [Desc; 16],
    avail_flags: u16,
    avail_idx: u16,
    avail_ring: [u16; 16],
    used_pad: [u8; 4],
    used_flags: u16,
    used_idx: u16,
    used_ring: [UsedElem; 16],
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
                let base = pci::map_bar(d, bar);
                let addr = base + off as u64;
                match t {
                    CAP_COMMON => common = addr,
                    CAP_NOTIFY => {
                        notify = addr;
                        notify_mul = pci::cfg_read32(d.bus, d.dev, d.func, cap as u16 + 16);
                    }
                    CAP_DEVICE => device = addr,
                    CAP_ISR => {}
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
        self.w8(0x14, 0); // device_status (offset in common cfg: after features)
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
        self.w32(8, 0);
        self.w32(12, 0); // no extra features
        self.w8(20, S_ACK | S_DRIVER | S_FEATURES_OK);
        let _ = self.r8(20);
    }

    pub unsafe fn setup_queue(&self, idx: u16) -> Virtq {
        self.w16(22, idx); // queue_select
        let size = 16u16;
        self.w16(24, size); // queue_size
        self.w16(26, 0xffff); // no msix
        let layout = core::alloc::Layout::from_size_align(
            core::mem::size_of::<SplitQ>(),
            16,
        )
        .unwrap();
        let q = alloc::alloc::alloc_zeroed(layout) as *mut SplitQ;
        let pa = q as u64;
        self.w64(32, pa); // queue_desc
        self.w64(40, pa + 16 * 16); // queue_driver (avail)
        self.w64(48, pa + 16 * 16 + 4 + 2 + 2 + 32); // approx used — recompute
        // SplitQ layout: desc 16*16=256, avail_flags+idx=4, ring 32, pad 4, used_flags+idx=4, used 16*8=128
        let avail_off = core::mem::offset_of!(SplitQ, avail_flags) as u64;
        let used_off = core::mem::offset_of!(SplitQ, used_flags) as u64;
        self.w64(32, pa);
        self.w64(40, pa + avail_off);
        self.w64(48, pa + used_off);
        self.w16(28, 1); // queue_enable
        let n_off = self.r16(30) as u32; // queue_notify_off
        let notify = self.notify.add((n_off * self.notify_off_mul) as usize) as *mut u16;
        Virtq { q, last_used: 0, notify }
    }

    pub unsafe fn driver_ok(&self) {
        self.w8(20, S_ACK | S_DRIVER | S_FEATURES_OK | S_DRIVER_OK);
    }
}

impl Virtq {
    pub unsafe fn add_in(&mut self, buf: *mut u8, len: u32, id: u16) {
        let q = &mut *self.q;
        q.desc[id as usize] = Desc {
            addr: buf as u64,
            len,
            flags: 2, // WRITE (device writes)
            next: 0,
        };
        let idx = q.avail_idx;
        q.avail_ring[(idx % 16) as usize] = id;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        q.avail_idx = idx.wrapping_add(1);
        core::ptr::write_volatile(self.notify, 0);
    }

    pub unsafe fn add_out(&mut self, buf: *const u8, len: u32, id: u16) {
        let q = &mut *self.q;
        q.desc[id as usize] = Desc {
            addr: buf as u64,
            len,
            flags: 0,
            next: 0,
        };
        let idx = q.avail_idx;
        q.avail_ring[(idx % 16) as usize] = id;
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
        let e = q.used_ring[(self.last_used % 16) as usize];
        self.last_used = self.last_used.wrapping_add(1);
        Some((e.id as u16, e.len))
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
}
