use crate::c_abi::*;
use crate::header::{encode_ta_head, parse_ta_head, TaProperties, RTAH_MAGIC, RTAH_SIZE};
use crate::kernel_abi::{
    param_from_gp, KernelCmd, KernelOut, Login, Origin, Param, SessionId, TeeSyscall, Uuid,
};
use crate::param::{TeeParam, TeeUuid};
use crate::property::{
    self, INTERNAL_CORE_VERSION, MAX_BIGINT_BITS, PROPSET_TA, PROPSET_TEE, PROT_LEVEL_NONE,
};
use crate::runtime;
use crate::*;
use core::ffi::c_void;

extern crate std;
use std::string::String;
use std::vec::Vec;

fn reset() {
    runtime::reset_for_test();
}

#[test]
fn identifiers() {
    assert_eq!(TEE_SUCCESS, 0);
    assert_eq!(TEE_ERROR_NOT_SUPPORTED, 0xFFFF000A);
    assert_eq!(TEE_ERROR_TARGET_DEAD, 0xFFFF3024);
    assert_eq!(TEE_LOGIN_USER_APPLICATION, 5);
    assert_eq!(TEE_LOGIN_GROUP_APPLICATION, 6);
    assert_eq!(TEE_LOGIN_TRUSTED_APP, 0xF0000000);
    assert_eq!(RTAH_MAGIC, 0x4841_5452);
    assert_eq!(TEE_NUM_PARAMS, 4);
}

#[test]
fn header_roundtrip_matches_kernel_layout() {
    let p = TaProperties {
        uuid: Uuid([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]),
        stack_size: 0x1111_2222,
        data_size: 0x3333_4444,
        single_instance: true,
        multi_session: false,
        instance_keep_alive: true,
        endian: 0,
        ta_version: 0xAABB_CCDD,
    };
    let b = encode_ta_head(&p);
    assert_eq!(b.len(), 40);
    assert_eq!(RTAH_SIZE, 40);
    assert_eq!(u32::from_le_bytes(b[0..4].try_into().unwrap()), 0x4841_5452);
    assert_eq!(u16::from_le_bytes(b[4..6].try_into().unwrap()), 0);
    assert_eq!(u16::from_le_bytes(b[6..8].try_into().unwrap()), 40);
    assert_eq!(&b[8..24], &p.uuid.0);
    assert_eq!(u32::from_le_bytes(b[24..28].try_into().unwrap()), p.stack_size);
    assert_eq!(u32::from_le_bytes(b[28..32].try_into().unwrap()), p.data_size);
    assert_eq!(b[32], 1);
    assert_eq!(b[33], 0);
    assert_eq!(b[34], 1);
    assert_eq!(b[35], 0);
    assert_eq!(u32::from_le_bytes(b[36..40].try_into().unwrap()), p.ta_version);
    assert_eq!(parse_ta_head(&b), Some(p));
}

#[test]
fn param_nibble_conversion() {
    assert!(matches!(param_from_gp(0, 0, 0, 0, 0, 0), Ok(Param::None)));
    assert!(matches!(
        param_from_gp(1, 0, 9, 8, 0, 0),
        Ok(Param::Value {
            a: 9,
            b: 8,
            dir: Dir::In
        })
    ));
    assert!(matches!(
        param_from_gp(2, 0, 1, 2, 0, 0),
        Ok(Param::Value {
            a: 1,
            b: 2,
            dir: Dir::Out
        })
    ));
    assert!(matches!(
        param_from_gp(3, 0, 0, 0, 0, 0),
        Ok(Param::Value { dir: Dir::InOut, .. })
    ));
    assert!(matches!(
        param_from_gp(5, 0, 0, 0, 0x1000, 16),
        Ok(Param::Memref { dir: Dir::In, size: 16, .. })
    ));
    assert_eq!(param_from_gp(4, 0, 0, 0, 0, 0), Err(TEE_ERROR_BAD_PARAMETERS));
    let types = param_types(0, 4, 0, 0);
    assert_eq!(
        param_from_gp(types, 1, 0, 0, 0, 0),
        Err(TEE_ERROR_BAD_PARAMETERS)
    );
}

#[test]
fn frozen_properties() {
    reset();
    let ctx = property::PropCtx::new();
    assert_eq!(
        property::get_u32(&ctx, PROPSET_TEE, "gpd.tee.internalCore.version").unwrap(),
        0x0103_0100
    );
    assert_eq!(
        property::get_u64(&ctx, PROPSET_TEE, "gpd.tee.internalCore.version").unwrap(),
        0x0103_0100
    );
    assert_eq!(INTERNAL_CORE_VERSION, 0x0103_0100);
    assert_eq!(
        property::get_u32(&ctx, PROPSET_TEE, "gpd.tee.arith.maxBigIntSize").unwrap(),
        4096
    );
    assert_eq!(MAX_BIGINT_BITS, 4096);
    assert_eq!(
        property::get_u32(&ctx, PROPSET_TEE, "gpd.tee.systemTime.protectionLevel").unwrap(),
        0
    );
    assert_eq!(
        property::get_u32(
            &ctx,
            PROPSET_TEE,
            "gpd.tee.TAPersistentTime.protectionLevel"
        )
        .unwrap(),
        0
    );
    assert_eq!(PROT_LEVEL_NONE, 0);
    assert_eq!(
        property::get_bool(
            &ctx,
            PROPSET_TA,
            "gpd.ta.doesNotCloseHandleOnCorruptObject"
        )
        .unwrap(),
        false
    );
    let mut u32v = 0u32;
    let mut u64v = 0u64;
    let name = b"gpd.tee.internalCore.version\0";
    assert_eq!(
        TEE_GetPropertyAsU32(
            propset_tee(),
            name.as_ptr() as *const i8,
            &mut u32v
        ),
        TEE_SUCCESS
    );
    assert_eq!(u32v, 0x0103_0100);
    assert_eq!(
        TEE_GetPropertyAsU64(
            propset_tee(),
            name.as_ptr() as *const i8,
            &mut u64v
        ),
        TEE_SUCCESS
    );
    assert_eq!(u64v, 0x0103_0100);
}

#[test]
fn malloc_size_zero_non_null() {
    reset();
    let p = TEE_Malloc(0, TEE_MALLOC_FILL_ZERO);
    assert!(!p.is_null());
    TEE_Free(p);
}

#[test]
#[should_panic]
fn malloc_no_fill_without_no_share_panics() {
    reset();
    let _ = crate::runtime::malloc(8, TEE_MALLOC_NO_FILL);
}

#[derive(Default)]
struct FakeKernel {
    cmds: Vec<KernelCmd>,
}

impl TeeSyscall for FakeKernel {
    fn handle(&mut self, cmd: KernelCmd) -> KernelOut {
        self.cmds.push(cmd.clone());
        match &cmd {
            KernelCmd::OpenSession { .. } => KernelOut::Done {
                result: crate::kernel_abi::TeeResult {
                    code: TEE_SUCCESS,
                    origin: Origin::TrustedApp,
                },
                session: Some(SessionId(7)),
                params: [
                    Param::Value {
                        a: 0xA,
                        b: 0xB,
                        dir: Dir::Out,
                    },
                    Param::None,
                    Param::None,
                    Param::None,
                ],
            },
            KernelCmd::CloseSession { .. } | KernelCmd::Invoke { .. } => KernelOut::Done {
                result: crate::kernel_abi::TeeResult {
                    code: TEE_SUCCESS,
                    origin: Origin::Tee,
                },
                session: None,
                params: [Param::None; 4],
            },
            KernelCmd::Cancel { .. } => KernelOut::Done {
                result: crate::kernel_abi::TeeResult {
                    code: TEE_SUCCESS,
                    origin: Origin::Tee,
                },
                session: None,
                params: [Param::None; 4],
            },
        }
    }
}

#[test]
fn close_null_session_is_noop() {
    reset();
    let mut fake = FakeKernel::default();
    with_syscall(&mut fake, || {
        TEE_CloseTASession(core::ptr::null_mut());
    });
    assert!(fake.cmds.is_empty());
}

#[test]
fn open_ta_session_trusted_app_timeout_copy_out() {
    reset();
    let caller = Uuid([0x11; 16]);
    runtime::configure_ta(
        TaProperties {
            uuid: caller,
            stack_size: 4096,
            data_size: 4096,
            single_instance: true,
            multi_session: false,
            instance_keep_alive: false,
            endian: 0,
            ta_version: 1,
        },
        "0.1.0",
        "test",
    );
    let dest = TeeUuid::from_uuid(Uuid([0x22; 16]));
    let mut params = [TeeParam::value(0, 0); 4];
    let mut session: TeeTaSessionHandle = core::ptr::null_mut();
    let mut origin = 0u32;
    let mut fake = FakeKernel::default();
    let rc = with_syscall(&mut fake, || {
        TEE_OpenTASession(
            &dest,
            1234,
            param_types(TEE_PARAM_TYPE_VALUE_OUTPUT, 0, 0, 0),
            params.as_mut_ptr(),
            &mut session,
            &mut origin,
        )
    });
    assert_eq!(rc, TEE_SUCCESS);
    assert_eq!(origin, TEE_ORIGIN_TRUSTED_APP);
    assert!(!session.is_null());
    unsafe {
        assert_eq!(params[0].value.a, 0xA);
        assert_eq!(params[0].value.b, 0xB);
    }
    match &fake.cmds[0] {
        KernelCmd::OpenSession {
            uuid,
            login,
            timeout_ms,
            cancel_id,
            ..
        } => {
            assert_eq!(*uuid, Uuid([0x22; 16]));
            match login {
                Login::TrustedApp { uuid } => assert_eq!(*uuid, caller),
                other => panic!("login {other:?}"),
            }
            assert_eq!(*timeout_ms, 1234);
            assert_ne!(*cancel_id, 0);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn enumerator_walks_names() {
    reset();
    let mut e: TeePropSetHandle = core::ptr::null_mut();
    assert_eq!(TEE_AllocatePropertyEnumerator(&mut e), TEE_SUCCESS);
    TEE_StartPropertyEnumerator(e, propset_tee());
    let mut names: Vec<String> = Vec::new();
    loop {
        let mut buf = [0u8; 128];
        let mut len = buf.len();
        let r = TEE_GetPropertyName(e, buf.as_mut_ptr() as *mut c_void, &mut len);
        if r != TEE_SUCCESS {
            break;
        }
        let s = core::str::from_utf8(&buf[..len.saturating_sub(1)]).unwrap();
        names.push(String::from(s));
        if TEE_GetNextProperty(e) != TEE_SUCCESS {
            break;
        }
    }
    TEE_FreePropertyEnumerator(e);
    assert!(names.iter().any(|n| n == "gpd.tee.internalCore.version"));
    assert!(names.iter().any(|n| n == "gpd.tee.arith.maxBigIntSize"));
    assert!(names
        .iter()
        .any(|n| n == "gpd.tee.systemTime.protectionLevel"));
}

#[test]
fn open_rejects_nibble_four_origin_api() {
    reset();
    let dest = TeeUuid::from_uuid(Uuid([0x22; 16]));
    let mut params = [TeeParam::none(); 4];
    let mut session: TeeTaSessionHandle = core::ptr::null_mut();
    let mut origin = 0u32;
    let mut fake = FakeKernel::default();
    let rc = with_syscall(&mut fake, || {
        TEE_OpenTASession(
            &dest,
            0,
            param_types(4, 0, 0, 0),
            params.as_mut_ptr(),
            &mut session,
            &mut origin,
        )
    });
    assert_eq!(rc, TEE_ERROR_BAD_PARAMETERS);
    assert_eq!(origin, TEE_ORIGIN_API);
    assert!(fake.cmds.is_empty());
}

#[test]
fn algorithm_supported_forwards_element() {
    assert_eq!(
        TEE_IsAlgorithmSupported(TEE_ALG_SHA256, TEE_CRYPTO_ELEMENT_NONE),
        TEE_SUCCESS
    );
    assert_eq!(
        TEE_IsAlgorithmSupported(TEE_ALG_HKDF, TEE_CRYPTO_ELEMENT_NONE),
        TEE_ERROR_NOT_SUPPORTED
    );
    assert_eq!(
        TEE_IsAlgorithmSupported(TEE_ALG_AES_ECB_NOPAD, TEE_CRYPTO_ELEMENT_NONE),
        TEE_SUCCESS
    );
    assert!(crate::crypto_api::is_algorithm_supported(
        TEE_ALG_ECDSA_SHA256,
        TEE_CRYPTO_ELEMENT_NONE
    ));
    assert!(crate::crypto_api::is_algorithm_supported(
        TEE_ALG_ECDSA_SHA256,
        TEE_ECC_CURVE_NIST_P256
    ));
    assert!(!crate::crypto_api::is_algorithm_supported(
        TEE_ALG_ECDSA_SHA256,
        1
    ));
    assert!(!crate::crypto_api::is_algorithm_supported(
        TEE_ALG_SHA256,
        TEE_ECC_CURVE_NIST_P256
    ));
}

#[test]
fn arith_init_then_crypto_op() {
    reset();
    let mut a = [0xAAu32; 8];
    crate::arith::init(&mut a);
    crate::arith::from_s32(&mut a, 21);
    assert_eq!(crate::arith::to_s32(&a), 21);
    let mut b = [0u32; 8];
    crate::arith::init(&mut b);
    crate::arith::from_s32(&mut b, 21);
    let mut c = [0u32; 8];
    crate::arith::init(&mut c);
    crate::arith::add(&mut c, &a, &b);
    assert_eq!(crate::arith::to_s32(&c), 42);
    let fmm = crate::arith::fmm_size_in_u32(2048);
    let ctx = crate::arith::fmm_context_size_in_u32(2048);
    assert_eq!(fmm, rustee_crypto::arith::fmm_size_in_u32(2048));
    assert_eq!(ctx, rustee_crypto::arith::fmm_context_size_in_u32(2048));
    assert_ne!(fmm, 0);
    assert_ne!(ctx, 0);
    assert_eq!(TEE_BigIntFMMSizeInU32(2048), fmm);
    assert_eq!(TEE_BigIntFMMContextSizeInU32(2048), ctx);
    let mut buf = [0u32; 8];
    TEE_BigIntInit(buf.as_mut_ptr(), buf.len());
    crate::arith::from_s32(&mut buf, 7);
    assert_eq!(crate::arith::to_s32(&buf), 7);
    let mut modulus = [0u32; 8];
    crate::arith::init(&mut modulus);
    crate::arith::from_s32(&mut modulus, 17);
    let mut fctx = [0u32; 16];
    assert_eq!(
        TEE_BigIntInitFMMContext1(fctx.as_mut_ptr(), fctx.len(), modulus.as_ptr()),
        TEE_SUCCESS
    );
    let mut short = [0u8; 0];
    crate::arith::from_s32(&mut a, 255);
    assert_eq!(
        crate::arith::to_octet_string(&a, &mut short),
        Err(TEE_ERROR_SHORT_BUFFER)
    );
}

struct FakeStore {
    items: Vec<crate::ObjectMeta>,
}

impl runtime::PersistentStore for FakeStore {
    fn list(
        &mut self,
        _ta: [u8; 16],
    ) -> Result<Vec<crate::ObjectMeta>, crate::StorageError> {
        Ok(self.items.clone())
    }
}

#[test]
fn persistent_object_enumerator() {
    reset();
    let mut fake = FakeStore {
        items: std::vec![
            crate::ObjectMeta {
                object_id: b"one".to_vec(),
                flags: 1,
                data_size: 10,
            },
            crate::ObjectMeta {
                object_id: b"two".to_vec(),
                flags: 2,
                data_size: 20,
            },
        ],
    };
    with_persistent_store(&mut fake, || {
        let mut e: TeeObjectEnumHandle = core::ptr::null_mut();
        assert_eq!(TEE_AllocatePersistentObjectEnumerator(&mut e), TEE_SUCCESS);
        assert_eq!(
            TEE_StartPersistentObjectEnumerator(e, TEE_STORAGE_PRIVATE),
            TEE_SUCCESS
        );
        let mut info = crate::param::TeeObjectInfo::default();
        let mut id = [0u8; 16];
        let mut id_len = id.len();
        assert_eq!(
            TEE_GetNextPersistentObject(e, &mut info, id.as_mut_ptr() as *mut c_void, &mut id_len),
            TEE_SUCCESS
        );
        assert_eq!(&id[..id_len], b"one");
        assert_eq!(info.data_size, 10);
        assert_eq!(info.handle_flags, 1);
        id_len = id.len();
        assert_eq!(
            TEE_GetNextPersistentObject(e, &mut info, id.as_mut_ptr() as *mut c_void, &mut id_len),
            TEE_SUCCESS
        );
        assert_eq!(&id[..id_len], b"two");
        id_len = id.len();
        assert_eq!(
            TEE_GetNextPersistentObject(e, &mut info, id.as_mut_ptr() as *mut c_void, &mut id_len),
            TEE_ERROR_ITEM_NOT_FOUND
        );
        TEE_ResetPersistentObjectEnumerator(e);
        id_len = id.len();
        assert_eq!(
            TEE_GetNextPersistentObject(e, &mut info, id.as_mut_ptr() as *mut c_void, &mut id_len),
            TEE_SUCCESS
        );
        assert_eq!(&id[..id_len], b"one");
        assert_eq!(
            TEE_StartPersistentObjectEnumerator(e, TEE_STORAGE_PRIVATE),
            TEE_SUCCESS
        );
        id_len = id.len();
        assert_eq!(
            TEE_GetNextPersistentObject(e, &mut info, id.as_mut_ptr() as *mut c_void, &mut id_len),
            TEE_SUCCESS
        );
        assert_eq!(&id[..id_len], b"one");
        assert_eq!(
            TEE_StartPersistentObjectEnumerator(e, TEE_STORAGE_PERSO),
            TEE_ERROR_NOT_SUPPORTED
        );
        assert_eq!(
            TEE_StartPersistentObjectEnumerator(e, TEE_STORAGE_PROTECTED),
            TEE_ERROR_NOT_SUPPORTED
        );
        TEE_FreePersistentObjectEnumerator(e);
        TEE_FreePersistentObjectEnumerator(core::ptr::null_mut());
    });
}

#[test]
fn ree_fs_persistent_store_list() {
    reset();
    struct Ctr(u8);
    impl rustee_hal::Entropy for Ctr {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
        fn origin(&self) -> rustee_hal::EntropyOrigin {
            rustee_hal::EntropyOrigin::Isolated
        }
    }
    struct TestHuk;
    impl rustee_hal::Huk for TestHuk {
        fn material(&self) -> &[u8] {
            b"0123456789abcdef0123456789abcdef"
        }
    }
    let mut ree = rustee_storage::ReeFs::new(Ctr(1), TestHuk, rustee_storage::MemFs::new());
    // enumerator lists the current TA uuid (reset default is zeros)
    ree.create([0u8; 16], b"oid-1", 0, b"hello").unwrap();
    with_persistent_store(&mut ree, || {
        let mut e: TeeObjectEnumHandle = core::ptr::null_mut();
        assert_eq!(TEE_AllocatePersistentObjectEnumerator(&mut e), TEE_SUCCESS);
        assert_eq!(
            TEE_StartPersistentObjectEnumerator(e, TEE_STORAGE_PRIVATE),
            TEE_SUCCESS
        );
        let mut info = crate::param::TeeObjectInfo::default();
        let mut id = [0u8; 16];
        let mut id_len = id.len();
        assert_eq!(
            TEE_GetNextPersistentObject(e, &mut info, id.as_mut_ptr() as *mut c_void, &mut id_len),
            TEE_SUCCESS
        );
        assert_eq!(&id[..id_len], b"oid-1");
        TEE_FreePersistentObjectEnumerator(e);
    });
}
