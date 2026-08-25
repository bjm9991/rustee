//! Host Client API (GPD_SPE_007). Header name MUST be tee_client_api.h when the C ABI lands.
//! TEEC_CONFIG_PAYLOAD_REF_COUNT = 4. TEEC_CONFIG_SHAREDMEM_MAX_SIZE >= 512 KiB.

pub const TEEC_CONFIG_PAYLOAD_REF_COUNT: u32 = 4;
pub const TEEC_CONFIG_SHAREDMEM_MAX_SIZE: u32 = 0x80000;
pub const TEEC_SUCCESS: u32 = 0;

#[cfg(test)]
mod tests {
    #[test]
    fn four_params() {
        assert_eq!(super::TEEC_CONFIG_PAYLOAD_REF_COUNT, 4);
        assert!(super::TEEC_CONFIG_SHAREDMEM_MAX_SIZE >= 0x80000);
    }
}
