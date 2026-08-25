//! Host CA smoke. Loopback covers packing; `hello-ca` talks CID 3:7007.

#[cfg(test)]
mod tests {
    use gp_client::{Context, Loopback, Uuid, HELLO_RS_UUID_BYTES, TEEC_LOGIN_PUBLIC};

    #[test]
    fn client_payload() {
        assert_eq!(gp_client::TEEC_CONFIG_PAYLOAD_REF_COUNT, 4);
    }

    #[test]
    fn hello_cmd0_shm_loopback() {
        let mut ctx = Context::new(Loopback::default());
        ctx.initialize().unwrap();
        let sid = ctx
            .open_session(&Uuid::from_bytes(HELLO_RS_UUID_BYTES), TEEC_LOGIN_PUBLIC)
            .unwrap();
        let mut dst = [0u8; 16];
        let n = ctx.invoke_shm(sid, 0, b"hello-rs", &mut dst).unwrap();
        assert_eq!(&dst[..n], b"hello-rs");
        ctx.close_session(sid).unwrap();
    }
}
