//! Thin-forward crypto. SHALL table lives in rustee-crypto, not here.

use rustee_crypto::alg::ELEMENT_NONE;
use rustee_crypto::{CryptoProvider, SoftwareProvider};

pub fn is_algorithm_supported(alg: u32, element: u32) -> bool {
    if element == ELEMENT_NONE {
        SoftwareProvider.is_supported(alg)
    } else {
        SoftwareProvider.is_supported_element(alg, element)
    }
}

pub fn generate_random(buf: *mut u8, len: usize) {
    if len == 0 {
        return;
    }
    if buf.is_null() {
        crate::panic_api::tee_panic(crate::TEE_ERROR_BAD_PARAMETERS);
    }
    let sl = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    crate::runtime::fill_entropy(sl);
}
