#![no_std]
//! Privileged TEE kernel. `Kernel<H: Hal, C: CryptoProvider>`.
//!
//! Inbound: CallGate::recv → proto → [`Kernel::handle`].
//! Outbound RPC: [`KernelOut::Rpc`] then CallGate::rpc_yield; resume
//! [`KernelCmd::RpcComplete`]. Never `Hal::rpc`. Never MSG.
//!
//! Guest target: `aarch64-unknown-none`. Traits are ISA-neutral.

extern crate alloc;

mod abi;
mod header;
mod instance;
mod loader;
mod pta;
mod session;

pub use abi::*;
pub use header::{
    encode_ta_head, parse_ta_head, TaProperties, RTAH_MAGIC, RTAH_SIZE, SECTION_NAME, V0_DEV_PUBKEY,
};
pub use loader::{load_image, EarlyTa};
pub use pta::{Pta, PtaRegistry};

use header::encode_ta_head as encode_head;
use instance::{Instance, InstanceState, InstanceTable};
use loader::{EarlyTas, Loaded};
use rustee_crypto::CryptoProvider;
use rustee_hal::{EntropyOrigin, Hal, TaAddressSpace};
use session::{Session, SessionKind, SessionState, SessionTable};

const MAX_SESSIONS: usize = 32;
const MAX_INSTANCES: usize = 16;

/// Fallback if the virt backend does not pass HAL notices. Same text as rustee-hal-virt.
pub const VIRT_ENTROPY_NOTICE: &str =
    "RUSTEE entropy is REE-sourced (virt/host); not a product TEE RNG";
pub const VIRT_HUK_NOTICE: &str =
    "RUSTEE HUK is a compile-time test key (virt); not a product HUK";

enum Yielding {
    LoadTa {
        uuid: Uuid,
        login: Login,
        params: [Param; PARAM_COUNT],
        cancel_id: u32,
        timeout_ms: u32,
    },
}

pub struct Kernel<H: Hal, C: CryptoProvider = rustee_crypto::SoftwareProvider> {
    crypto: C,
    entropy_origin: EntropyOrigin,
    sessions: SessionTable,
    instances: InstanceTable<H>,
    ptas: PtaRegistry,
    early: EarlyTas,
    yielding: Option<Yielding>,
    current_instance: Option<InstanceId>,
    cancelled: alloc::vec::Vec<u32>,
    _h: core::marker::PhantomData<H>,
}

impl<H: Hal, C: CryptoProvider> Kernel<H, C> {
    pub fn new(crypto: C, entropy_origin: EntropyOrigin) -> Self {
        Self {
            crypto,
            entropy_origin,
            sessions: SessionTable::new(MAX_SESSIONS),
            instances: InstanceTable::new(MAX_INSTANCES),
            ptas: PtaRegistry::new(),
            early: EarlyTas::new(),
            yielding: None,
            current_instance: None,
            cancelled: alloc::vec::Vec::new(),
            _h: core::marker::PhantomData,
        }
    }

    /// HAL has no console. If entropy is ReeHost, write HAL notices (or fallbacks).
    /// Must not continue silently.
    pub fn emit_ree_notices<W: core::fmt::Write>(
        &self,
        out: &mut W,
        notices: Option<[&str; 2]>,
    ) -> core::fmt::Result {
        if self.entropy_origin != EntropyOrigin::ReeHost {
            return Ok(());
        }
        let n = notices.unwrap_or([VIRT_ENTROPY_NOTICE, VIRT_HUK_NOTICE]);
        writeln!(out, "{}", n[0])?;
        writeln!(out, "{}", n[1])
    }

    pub fn register_pta(&mut self, pta: alloc::boxed::Box<dyn Pta>) {
        self.ptas.register(pta);
    }

    pub fn register_early_ta(&mut self, ta: EarlyTa) {
        self.early.insert(ta);
    }

    pub fn handle(&mut self, cmd: KernelCmd) -> KernelOut {
        match cmd {
            KernelCmd::OpenSession {
                uuid,
                login,
                params,
                cancel_id,
                timeout_ms,
            } => self.open(uuid, login, params, cancel_id, timeout_ms),
            KernelCmd::Invoke {
                session,
                cmd_id,
                params,
                cancel_id,
                timeout_ms,
            } => {
                let _ = timeout_ms;
                self.invoke(session, cmd_id, params, cancel_id)
            }
            KernelCmd::CloseSession { session } => self.close(session),
            KernelCmd::Cancel { cancel_id } => {
                self.cancelled.push(cancel_id);
                KernelOut::done_err(TEE_SUCCESS)
            }
            KernelCmd::RpcComplete { resp } => self.rpc_complete(resp),
        }
    }

    /// TA panic: poison that instance and its sessions only. Returns TARGET_DEAD.
    pub fn on_ta_panic(&mut self) -> KernelOut {
        if let Some(id) = self.current_instance.take() {
            if let Some(inst) = self.instances.get_mut(id) {
                inst.state = InstanceState::Dead;
                if let Some(aspace) = inst.aspace.take() {
                    aspace.drop_all();
                }
            }
            self.sessions.poison_instance(id);
        }
        KernelOut::done_err(TEE_ERROR_TARGET_DEAD)
    }

    fn cancelled(&self, cancel_id: u32) -> bool {
        self.cancelled.iter().any(|&c| c == cancel_id)
    }

    fn open(
        &mut self,
        uuid: Uuid,
        login: Login,
        mut params: [Param; PARAM_COUNT],
        cancel_id: u32,
        timeout_ms: u32,
    ) -> KernelOut {
        if self.cancelled(cancel_id) {
            return KernelOut::done_err(TEE_ERROR_CANCEL);
        }
        if let Some(pta) = self.ptas.get_mut(uuid) {
            match pta.open(&mut params) {
                Ok(ctx) => {
                    let sess = Session {
                        id: SessionId(0),
                        uuid,
                        kind: SessionKind::Pta,
                        instance: None,
                        ta_sess_ctx: ctx,
                        state: SessionState::Ready,
                        client: login,
                    };
                    match self.sessions.alloc(sess) {
                        Some(id) => KernelOut::Done {
                            result: TeeResult::ok(),
                            session: Some(id),
                            params,
                        },
                        None => KernelOut::done_err(TEE_ERROR_OUT_OF_MEMORY),
                    }
                }
                Err(e) => KernelOut::Done {
                    result: e,
                    session: None,
                    params,
                },
            }
        } else {
            self.open_user_ta(uuid, login, params, cancel_id, timeout_ms)
        }
    }

    fn open_user_ta(
        &mut self,
        uuid: Uuid,
        login: Login,
        params: [Param; PARAM_COUNT],
        cancel_id: u32,
        timeout_ms: u32,
    ) -> KernelOut {
        if self.cancelled(cancel_id) {
            return KernelOut::done_err(TEE_ERROR_CANCEL);
        }
        if let Some(id) = self.instances.live_single(uuid) {
            let inst = self.instances.get(id).unwrap();
            if !inst.props.multi_session && inst.session_count > 0 {
                // timeout_ms is how long we'd wait; v0 has one yielding call and
                // no instance wait loop yet, so busy is immediate. Cancel still wins.
                let _ = timeout_ms;
                return KernelOut::done_err(TEE_ERROR_BUSY);
            }
            return self.bind_session(id, uuid, login, params);
        }
        if let Some(early) = self.early.get(uuid).cloned() {
            return self.instantiate_and_bind(early.props, uuid, login, params);
        }
        if self.yielding.is_some() {
            return KernelOut::done_err(TEE_ERROR_BUSY);
        }
        self.yielding = Some(Yielding::LoadTa {
            uuid,
            login,
            params,
            cancel_id,
            timeout_ms,
        });
        KernelOut::Rpc(HalRpc::LoadTa { uuid })
    }

    fn instantiate_and_bind(
        &mut self,
        props: TaProperties,
        uuid: Uuid,
        login: Login,
        params: [Param; PARAM_COUNT],
    ) -> KernelOut {
        if props.uuid != uuid {
            return KernelOut::done_err(TEE_ERROR_SECURITY);
        }
        let inst = Instance::<H> {
            id: InstanceId(0),
            uuid,
            props,
            aspace: None,
            session_count: 0,
            state: InstanceState::Live,
        };
        let Some(iid) = self.instances.alloc(inst) else {
            return KernelOut::done_err(TEE_ERROR_OUT_OF_MEMORY);
        };
        self.bind_session(iid, uuid, login, params)
    }

    fn bind_session(
        &mut self,
        iid: InstanceId,
        uuid: Uuid,
        login: Login,
        params: [Param; PARAM_COUNT],
    ) -> KernelOut {
        let sess = Session {
            id: SessionId(0),
            uuid,
            kind: SessionKind::UserTa,
            instance: Some(iid),
            ta_sess_ctx: 0,
            state: SessionState::Ready,
            client: login,
        };
        match self.sessions.alloc(sess) {
            Some(sid) => {
                if let Some(inst) = self.instances.get_mut(iid) {
                    inst.session_count = inst.session_count.saturating_add(1);
                }
                KernelOut::Done {
                    result: TeeResult::ok(),
                    session: Some(sid),
                    params,
                }
            }
            None => KernelOut::done_err(TEE_ERROR_OUT_OF_MEMORY),
        }
    }

    fn invoke(
        &mut self,
        session: SessionId,
        cmd_id: u32,
        mut params: [Param; PARAM_COUNT],
        cancel_id: u32,
    ) -> KernelOut {
        if self.cancelled(cancel_id) {
            return KernelOut::done_err(TEE_ERROR_CANCEL);
        }
        let Some(sess) = self.sessions.get(session).copied() else {
            return KernelOut::done_err(TEE_ERROR_BAD_PARAMETERS);
        };
        if sess.state == SessionState::Dead {
            return KernelOut::done_err(TEE_ERROR_TARGET_DEAD);
        }
        match sess.kind {
            SessionKind::Pta => {
                if let Some(pta) = self.ptas.get_mut(sess.uuid) {
                    let r = pta.invoke(sess.ta_sess_ctx, cmd_id, &mut params);
                    KernelOut::Done {
                        result: r,
                        session: Some(session),
                        params,
                    }
                } else {
                    KernelOut::done_err(TEE_ERROR_ITEM_NOT_FOUND)
                }
            }
            SessionKind::UserTa => {
                // REE memrefs: register → sync_in → map_into → invoke → sync_out
                // is HAL SharedMem. EXEC+SHM is illegal (rejected when mapping).
                // TA-to-TA MemrefSrc::Ta skips the bounce pool.
                self.current_instance = sess.instance;
                let _ = cmd_id;
                self.current_instance = None;
                KernelOut::Done {
                    result: TeeResult::ok(),
                    session: Some(session),
                    params,
                }
            }
        }
    }

    fn close(&mut self, session: SessionId) -> KernelOut {
        let Some(sess) = self.sessions.take(session) else {
            return KernelOut::done_err(TEE_ERROR_BAD_PARAMETERS);
        };
        match sess.kind {
            SessionKind::Pta => {
                if let Some(pta) = self.ptas.get_mut(sess.uuid) {
                    pta.close(sess.ta_sess_ctx);
                }
            }
            SessionKind::UserTa => {
                if let Some(iid) = sess.instance {
                    if let Some(inst) = self.instances.get_mut(iid) {
                        inst.session_count = inst.session_count.saturating_sub(1);
                        if inst.session_count == 0 && !inst.props.instance_keep_alive {
                            inst.state = InstanceState::Dead;
                            if let Some(aspace) = inst.aspace.take() {
                                aspace.drop_all();
                            }
                            self.instances.drop_id(iid);
                        }
                    }
                }
            }
        }
        KernelOut::Done {
            result: TeeResult::ok(),
            session: None,
            params: [Param::None; PARAM_COUNT],
        }
    }

    fn rpc_complete(&mut self, resp: RpcResponse) -> KernelOut {
        let Some(y) = self.yielding.take() else {
            return KernelOut::done_err(TEE_ERROR_BAD_PARAMETERS);
        };
        match (y, resp) {
            (
                Yielding::LoadTa {
                    uuid,
                    login,
                    params,
                    cancel_id,
                    timeout_ms,
                },
                RpcResponse::LoadTa { bytes },
            ) => {
                if self.cancelled(cancel_id) {
                    return KernelOut::done_err(TEE_ERROR_CANCEL);
                }
                let _ = timeout_ms;
                match load_image(&self.crypto, &bytes) {
                    Ok(Loaded { props }) => {
                        if props.uuid != uuid {
                            KernelOut::done_err(TEE_ERROR_SECURITY)
                        } else {
                            self.instantiate_and_bind(props, uuid, login, params)
                        }
                    }
                    Err(code) => KernelOut::done_err(code),
                }
            }
            (_, RpcResponse::Error { code }) => KernelOut::done_err(code),
            _ => KernelOut::done_err(TEE_ERROR_NOT_SUPPORTED),
        }
    }
}

// Silence unused encode in non-test builds.
#[allow(dead_code)]
fn _encode(p: &TaProperties) -> [u8; 40] {
    encode_head(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustee_crypto::SoftwareProvider;
    use rustee_hal::{
        CallFrame, CallGate, Entropy, EntropyOrigin, Huk, SharedMem, ShmMapping, TaAddressSpace,
    };

    struct MockGate;
    impl CallGate for MockGate {
        type Error = ();
        fn recv(&mut self) -> Result<CallFrame, ()> {
            Err(())
        }
        fn complete(&mut self, _: CallFrame) -> Result<(), ()> {
            Err(())
        }
        fn rpc_yield(&mut self, _: CallFrame) -> Result<CallFrame, ()> {
            Err(())
        }
    }

    struct MockAs;
    impl TaAddressSpace for MockAs {
        type Error = ();
        fn map_image(&mut self, _: &[[u64; 2]]) -> Result<(), ()> {
            Ok(())
        }
        fn map_shm(&mut self, _: &impl ShmMapping, perms: u32) -> Result<u64, ()> {
            if perms & PERM_EXEC != 0 && perms & PERM_SHM != 0 {
                return Err(());
            }
            Ok(0)
        }
        fn unmap(&mut self, _: u64, _: usize) -> Result<(), ()> {
            Ok(())
        }
        fn drop_all(self) {}
    }

    struct MockShm;
    impl ShmMapping for MockShm {
        fn cookie(&self) -> u64 {
            0
        }
        fn len(&self) -> usize {
            0
        }
        fn perms(&self) -> u32 {
            PERM_READ | PERM_WRITE | PERM_SHM
        }
    }
    impl SharedMem for MockShm {
        type Error = ();
        fn sync_in(&mut self) -> Result<(), ()> {
            Ok(())
        }
        fn sync_out(&mut self) -> Result<(), ()> {
            Ok(())
        }
    }

    struct MockEnt;
    impl Entropy for MockEnt {
        fn fill(&mut self, buf: &mut [u8]) {
            buf.fill(0);
        }
        fn origin(&self) -> EntropyOrigin {
            EntropyOrigin::ReeHost
        }
    }
    struct MockHuk;
    impl Huk for MockHuk {
        fn material(&self) -> &[u8] {
            &[0u8; 32]
        }
    }

    struct MockHal;
    impl Hal for MockHal {
        type CallGate = MockGate;
        type AddressSpace = MockAs;
        type SharedMem = MockShm;
        type Entropy = MockEnt;
        type Huk = MockHuk;
        type Monotonic = ();
        type SecureTime = ();
        type Irq = ();
        type Error = ();
    }

    struct EchoPta(Uuid);
    impl Pta for EchoPta {
        fn uuid(&self) -> Uuid {
            self.0
        }
        fn open(&mut self, _: &mut [Param; PARAM_COUNT]) -> Result<usize, TeeResult> {
            Ok(1)
        }
        fn invoke(
            &mut self,
            _: usize,
            cmd: u32,
            params: &mut [Param; PARAM_COUNT],
        ) -> TeeResult {
            if let Param::Value { a, dir: Dir::Out, .. } = &mut params[0] {
                *a = cmd;
            }
            TeeResult::ta(TEE_SUCCESS)
        }
        fn close(&mut self, _: usize) {}
    }

    fn k() -> Kernel<MockHal, SoftwareProvider> {
        Kernel::new(SoftwareProvider, EntropyOrigin::ReeHost)
    }

    fn none_params() -> [Param; PARAM_COUNT] {
        [Param::None; PARAM_COUNT]
    }

    #[test]
    fn ree_notices_printed() {
        let k = k();
        let mut s = alloc::string::String::new();
        k.emit_ree_notices(&mut s, None).unwrap();
        assert!(s.contains("not a product TEE RNG"));
        assert!(s.contains("not a product HUK"));
    }

    #[test]
    fn pta_open_invoke_close() {
        let mut k = k();
        let uuid = Uuid([1; 16]);
        k.register_pta(alloc::boxed::Box::new(EchoPta(uuid)));
        let out = k.handle(KernelCmd::OpenSession {
            uuid,
            login: Login::Public,
            params: none_params(),
            cancel_id: 1,
            timeout_ms: TEE_TIMEOUT_INFINITE,
        });
        let sid = match out {
            KernelOut::Done {
                result,
                session,
                ..
            } => {
                assert_eq!(result.code, TEE_SUCCESS);
                session.unwrap()
            }
            _ => panic!("rpc"),
        };
        let mut params = none_params();
        params[0] = Param::Value {
            a: 0,
            b: 0,
            dir: Dir::Out,
        };
        let out = k.handle(KernelCmd::Invoke {
            session: sid,
            cmd_id: 42,
            params,
            cancel_id: 2,
            timeout_ms: TEE_TIMEOUT_INFINITE,
        });
        match out {
            KernelOut::Done { result, params, .. } => {
                assert_eq!(result.origin, Origin::TrustedApp);
                assert_eq!(
                    params[0],
                    Param::Value {
                        a: 42,
                        b: 0,
                        dir: Dir::Out
                    }
                );
            }
            _ => panic!(),
        }
        let out = k.handle(KernelCmd::CloseSession { session: sid });
        match out {
            KernelOut::Done { result, .. } => assert_eq!(result.code, TEE_SUCCESS),
            _ => panic!(),
        }
    }

    #[test]
    fn load_ta_rpc_then_complete() {
        let mut k = k();
        let uuid = Uuid([9; 16]);
        let props = TaProperties {
            uuid,
            stack_size: 4096,
            data_size: 8192,
            single_instance: true,
            multi_session: true,
            instance_keep_alive: false,
            endian: 0,
            ta_version: 1,
        };
        let bytes = encode_ta_head(&props).to_vec();
        let out = k.handle(KernelCmd::OpenSession {
            uuid,
            login: Login::TrustedApp {
                uuid: Uuid([2; 16]),
            },
            params: none_params(),
            cancel_id: 7,
            timeout_ms: TEE_TIMEOUT_INFINITE,
        });
        match out {
            KernelOut::Rpc(HalRpc::LoadTa { uuid: u }) => assert_eq!(u, uuid),
            other => panic!("{other:?}"),
        }
        let out = k.handle(KernelCmd::RpcComplete {
            resp: RpcResponse::LoadTa { bytes },
        });
        match out {
            KernelOut::Done {
                result,
                session,
                ..
            } => {
                assert_eq!(result.code, TEE_SUCCESS);
                assert!(session.is_some());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn single_session_busy() {
        let mut k = k();
        let uuid = Uuid([3; 16]);
        let props = TaProperties {
            uuid,
            stack_size: 4096,
            data_size: 4096,
            single_instance: true,
            multi_session: false,
            instance_keep_alive: false,
            endian: 0,
            ta_version: 1,
        };
        k.register_early_ta(EarlyTa {
            uuid,
            props,
            image: &[],
        });
        let open = |k: &mut Kernel<MockHal, SoftwareProvider>| {
            k.handle(KernelCmd::OpenSession {
                uuid,
                login: Login::Public,
                params: none_params(),
                cancel_id: 1,
                timeout_ms: 0,
            })
        };
        assert!(matches!(
            open(&mut k),
            KernelOut::Done {
                result: TeeResult {
                    code: TEE_SUCCESS,
                    ..
                },
                ..
            }
        ));
        match open(&mut k) {
            KernelOut::Done { result, .. } => assert_eq!(result.code, TEE_ERROR_BUSY),
            _ => panic!(),
        }
    }

    #[test]
    fn keep_alive_survives_last_close() {
        let mut k = k();
        let uuid = Uuid([4; 16]);
        let props = TaProperties {
            uuid,
            stack_size: 4096,
            data_size: 4096,
            single_instance: true,
            multi_session: true,
            instance_keep_alive: true,
            endian: 0,
            ta_version: 1,
        };
        k.register_early_ta(EarlyTa {
            uuid,
            props,
            image: &[],
        });
        let out = k.handle(KernelCmd::OpenSession {
            uuid,
            login: Login::Public,
            params: none_params(),
            cancel_id: 1,
            timeout_ms: TEE_TIMEOUT_INFINITE,
        });
        let sid = match out {
            KernelOut::Done { session, .. } => session.unwrap(),
            _ => panic!(),
        };
        k.handle(KernelCmd::CloseSession { session: sid });
        let out = k.handle(KernelCmd::OpenSession {
            uuid,
            login: Login::Public,
            params: none_params(),
            cancel_id: 2,
            timeout_ms: TEE_TIMEOUT_INFINITE,
        });
        match out {
            KernelOut::Done { result, session, .. } => {
                assert_eq!(result.code, TEE_SUCCESS);
                assert!(session.is_some());
            }
            KernelOut::Rpc(_) => panic!("keep-alive should reuse, not LOAD_TA"),
        }
    }

    #[test]
    fn ta_panic_kills_instance_not_kernel() {
        let mut k = k();
        let uuid = Uuid([5; 16]);
        k.register_early_ta(EarlyTa {
            uuid,
            props: TaProperties {
                uuid,
                stack_size: 4096,
                data_size: 4096,
                single_instance: true,
                multi_session: true,
                instance_keep_alive: true,
                endian: 0,
                ta_version: 1,
            },
            image: &[],
        });
        let sid = match k.handle(KernelCmd::OpenSession {
            uuid,
            login: Login::Public,
            params: none_params(),
            cancel_id: 1,
            timeout_ms: TEE_TIMEOUT_INFINITE,
        }) {
            KernelOut::Done { session, .. } => session.unwrap(),
            _ => panic!(),
        };
        k.current_instance = k.sessions.get(sid).and_then(|s| s.instance);
        let out = k.on_ta_panic();
        match out {
            KernelOut::Done { result, .. } => assert_eq!(result.code, TEE_ERROR_TARGET_DEAD),
            _ => panic!(),
        }
        match k.handle(KernelCmd::Invoke {
            session: sid,
            cmd_id: 1,
            params: none_params(),
            cancel_id: 2,
            timeout_ms: TEE_TIMEOUT_INFINITE,
        }) {
            KernelOut::Done { result, .. } => assert_eq!(result.code, TEE_ERROR_TARGET_DEAD),
            _ => panic!(),
        }
    }

    #[test]
    fn header_named_fields_not_flags() {
        let uuid = Uuid([6; 16]);
        let p = TaProperties {
            uuid,
            stack_size: 0x1000,
            data_size: 0x2000,
            single_instance: true,
            multi_session: true,
            instance_keep_alive: false,
            endian: 0,
            ta_version: 3,
        };
        let b = encode_ta_head(&p);
        assert_eq!(b.len(), 40);
        assert_eq!(u32::from_le_bytes(b[0..4].try_into().unwrap()), RTAH_MAGIC);
        assert_eq!(b[32], 1);
        assert_eq!(b[33], 1);
        assert_eq!(b[34], 0);
        assert_eq!(b[35], 0);
        let q = parse_ta_head(&b).unwrap();
        assert_eq!(q, p);
        let mut bad = p;
        bad.endian = 1;
        assert!(parse_ta_head(&encode_ta_head(&bad)).is_err());
        let mut bad = p;
        bad.single_instance = false;
        bad.multi_session = true;
        assert!(parse_ta_head(&encode_ta_head(&bad)).is_err());
    }

    #[test]
    fn cancel_beats_open() {
        let mut k = k();
        k.handle(KernelCmd::Cancel { cancel_id: 99 });
        match k.handle(KernelCmd::OpenSession {
            uuid: Uuid([7; 16]),
            login: Login::Public,
            params: none_params(),
            cancel_id: 99,
            timeout_ms: TEE_TIMEOUT_INFINITE,
        }) {
            KernelOut::Done { result, .. } => assert_eq!(result.code, TEE_ERROR_CANCEL),
            _ => panic!(),
        }
    }

    #[test]
    fn exec_plus_shm_illegal() {
        let mut aspace = MockAs;
        assert!(aspace
            .map_shm(&MockShm, PERM_EXEC | PERM_SHM)
            .is_err());
        assert!(aspace.map_shm(&MockShm, PERM_READ | PERM_SHM).is_ok());
    }
}
