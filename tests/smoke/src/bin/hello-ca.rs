//! Live CA: open hello-rs, invoke cmd 0 (memref 0 → 1), check shm.
//! Needs guest listen on CID 3:7007 (HAL virtio-vsock).
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use gp_client::wire::{vsock_transport, GUEST_CID, GUEST_PORT};
use gp_client::{Context, Uuid, HELLO_RS_UUID_BYTES, TEEC_LOGIN_PUBLIC};
use rustee_supplicant::Supplicant;

fn main() -> ExitCode {
    let root = env::var("RUSTEE_SUPP_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/rustee/supp"));
    match run(root) {
        Ok(n) => {
            eprintln!("hello-ca: cmd 0 copied {n} bytes");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("hello-ca: {e:#08x}");
            ExitCode::FAILURE
        }
    }
}

fn run(root: PathBuf) -> Result<usize, u32> {
    let supp = Supplicant::new(root).map_err(|_| 0xFFFF_000Eu32)?;
    rustee_supplicant::install(supp);
    let mut t = vsock_transport(GUEST_CID, GUEST_PORT)?;
    t.on_rpc = Some(rustee_supplicant::rpc_hook);
    let mut ctx = Context::new(t);
    ctx.initialize()?;
    let sid = ctx.open_session(&Uuid::from_bytes(HELLO_RS_UUID_BYTES), TEEC_LOGIN_PUBLIC)?;
    let mut dst = [0u8; 16];
    let n = ctx.invoke_shm(sid, 0, b"hello-rs", &mut dst)?;
    if &dst[..n] != b"hello-rs" {
        return Err(0xFFFF_000Fu32);
    }
    ctx.close_session(sid)?;
    Ok(n)
}
