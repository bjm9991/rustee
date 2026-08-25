use crate::abi::{Param, PARAM_COUNT, TeeResult, Uuid};

/// Privileged, UUID-routed, statically linked. PTA panic is a kernel halt.
pub trait Pta {
    fn uuid(&self) -> Uuid;
    fn open(&mut self, params: &mut [Param; PARAM_COUNT]) -> Result<usize, TeeResult>;
    fn invoke(
        &mut self,
        sess_ctx: usize,
        cmd: u32,
        params: &mut [Param; PARAM_COUNT],
    ) -> TeeResult;
    fn close(&mut self, sess_ctx: usize);
}

pub struct PtaRegistry {
    inner: alloc::vec::Vec<alloc::boxed::Box<dyn Pta>>,
}

impl PtaRegistry {
    pub fn new() -> Self {
        Self {
            inner: alloc::vec::Vec::new(),
        }
    }

    pub fn register(&mut self, pta: alloc::boxed::Box<dyn Pta>) {
        self.inner.push(pta);
    }

    pub fn get_mut(&mut self, uuid: Uuid) -> Option<&mut alloc::boxed::Box<dyn Pta>> {
        self.inner.iter_mut().find(|p| p.uuid() == uuid)
    }
}
