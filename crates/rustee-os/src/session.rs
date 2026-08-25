use crate::abi::{Login, SessionId, Uuid};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionKind {
    UserTa,
    Pta,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum SessionState {
    Opening,
    Ready,
    Busy,
    Closing,
    Dead,
}

#[derive(Clone, Copy, Debug)]
pub struct Session {
    pub id: SessionId,
    pub uuid: Uuid,
    pub kind: SessionKind,
    pub instance: Option<crate::abi::InstanceId>,
    pub ta_sess_ctx: usize,
    pub state: SessionState,
    #[allow(dead_code)]
    pub client: Login,
}

pub struct SessionTable {
    slots: alloc::vec::Vec<Option<Session>>,
    next_id: u32,
}

impl SessionTable {
    pub fn new(cap: usize) -> Self {
        let mut slots = alloc::vec::Vec::with_capacity(cap);
        slots.resize(cap, None);
        Self { slots, next_id: 1 }
    }

    pub fn alloc(&mut self, mut s: Session) -> Option<SessionId> {
        let id = SessionId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1).max(1);
        for slot in self.slots.iter_mut() {
            if slot.is_none() {
                s.id = id;
                *slot = Some(s);
                return Some(id);
            }
        }
        None
    }

    pub fn get(&self, id: SessionId) -> Option<&Session> {
        self.slots.iter().flatten().find(|s| s.id == id)
    }

    #[allow(dead_code)]
    pub fn get_mut(&mut self, id: SessionId) -> Option<&mut Session> {
        self.slots.iter_mut().flatten().find(|s| s.id == id)
    }

    pub fn take(&mut self, id: SessionId) -> Option<Session> {
        for slot in self.slots.iter_mut() {
            if slot.as_ref().map(|s| s.id) == Some(id) {
                return slot.take();
            }
        }
        None
    }

    pub fn poison_instance(&mut self, inst: crate::abi::InstanceId) {
        for s in self.slots.iter_mut().flatten() {
            if s.instance == Some(inst) {
                s.state = SessionState::Dead;
            }
        }
    }

    #[allow(dead_code)]
    pub fn count_for_instance(&self, inst: crate::abi::InstanceId) -> u16 {
        self.slots
            .iter()
            .flatten()
            .filter(|s| s.instance == Some(inst) && s.state != SessionState::Dead)
            .count() as u16
    }
}
