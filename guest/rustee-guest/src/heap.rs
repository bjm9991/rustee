use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

pub struct Bump {
    cur: AtomicUsize,
    end: AtomicUsize,
}

impl Bump {
    pub const fn empty() -> Self {
        Self {
            cur: AtomicUsize::new(0),
            end: AtomicUsize::new(0),
        }
    }
    pub fn init(&self, start: usize, len: usize) {
        self.cur.store(start, Ordering::Relaxed);
        self.end.store(start + len, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let a = layout.align().max(8);
        let end = self.end.load(Ordering::Relaxed);
        let mut cur = self.cur.load(Ordering::Relaxed);
        loop {
            let aligned = (cur + a - 1) & !(a - 1);
            let next = aligned.saturating_add(layout.size());
            if next > end {
                return core::ptr::null_mut();
            }
            match self
                .cur
                .compare_exchange(cur, next, Ordering::SeqCst, Ordering::Relaxed)
            {
                Ok(_) => return aligned as *mut u8,
                Err(c) => cur = c,
            }
        }
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static HEAP: Bump = Bump::empty();

pub fn init(start: usize, len: usize) {
    HEAP.init(start, len);
}
