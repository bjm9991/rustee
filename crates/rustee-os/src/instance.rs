use crate::abi::{InstanceId, TaEntryPoints, Uuid};
use crate::header::TaProperties;
use rustee_hal::Hal;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum InstanceState {
    Creating,
    Live,
    Dying,
    Dead,
}

pub struct Instance<H: Hal> {
    pub id: InstanceId,
    pub uuid: Uuid,
    pub props: TaProperties,
    pub aspace: Option<H::AddressSpace>,
    pub session_count: u16,
    pub state: InstanceState,
    pub entries: Option<TaEntryPoints>,
    pub busy: bool,
}

pub struct InstanceTable<H: Hal> {
    slots: alloc::vec::Vec<Option<Instance<H>>>,
    next_id: u32,
}

impl<H: Hal> InstanceTable<H> {
    pub fn new(cap: usize) -> Self {
        let mut slots = alloc::vec::Vec::with_capacity(cap);
        slots.resize_with(cap, || None);
        Self { slots, next_id: 1 }
    }

    pub fn live_single(&self, uuid: Uuid) -> Option<InstanceId> {
        self.slots.iter().flatten().find_map(|i| {
            if i.uuid == uuid && i.props.single_instance && i.state == InstanceState::Live {
                Some(i.id)
            } else {
                None
            }
        })
    }

    pub fn alloc(&mut self, mut inst: Instance<H>) -> Option<InstanceId> {
        let id = InstanceId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1).max(1);
        for slot in self.slots.iter_mut() {
            if slot.is_none() {
                inst.id = id;
                *slot = Some(inst);
                return Some(id);
            }
        }
        None
    }

    pub fn get(&self, id: InstanceId) -> Option<&Instance<H>> {
        self.slots.iter().flatten().find(|i| i.id == id)
    }

    pub fn get_mut(&mut self, id: InstanceId) -> Option<&mut Instance<H>> {
        self.slots.iter_mut().flatten().find(|i| i.id == id)
    }

    pub fn drop_id(&mut self, id: InstanceId) -> Option<Instance<H>> {
        for slot in self.slots.iter_mut() {
            if slot.as_ref().map(|i| i.id) == Some(id) {
                return slot.take();
            }
        }
        None
    }
}
