//! Live CA: open hello-rs, invoke cmd 0 (memref 0 → 1), check shm.
//! Needs guest listen on CID 3:7007 (HAL virtio-vsock).
//! OpenSession yields LOAD_TA; `on_rpc` copies `$SUPP_ROOT/ta/{uuid}.ta` into bounce.
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use gp_client::wire::{vsock_transport, GUEST_CID, GUEST_PORT};
use gp_client::{Context, Uuid, HELLO_RS_UUID_BYTES, HELLO_RS_UUID_HEX, TEEC_LOGIN_PUBLIC};
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

fn stage_hello_ta(root: &Path) -> Result<(), u32> {
    let dest = root.join("ta").join(format!("{HELLO_RS_UUID_HEX}.ta"));
    if dest.is_file() {
        return Ok(());
    }
    let Some(src) = env::var_os("RUSTEE_HELLO_TA").map(PathBuf::from) else {
        return Ok(());
    };
    fs::create_dir_all(dest.parent().ok_or(0xFFFF_000Eu32)?).map_err(|_| 0xFFFF_000Eu32)?;
    fs::copy(&src, &dest).map_err(|_| 0xFFFF_000Eu32)?;
    Ok(())
}

fn run(root: PathBuf) -> Result<usize, u32> {
    let supp = Supplicant::new(root.clone()).map_err(|_| 0xFFFF_000Eu32)?;
    stage_hello_ta(&root)?;
    rustee_supplicant::install(supp);
    eprintln!("hello-ca: connect {GUEST_CID}:{GUEST_PORT}");
    let mut t = vsock_transport(GUEST_CID, GUEST_PORT)?;
    eprintln!("hello-ca: connected");
    t.on_rpc = Some(rustee_supplicant::rpc_hook);
    let mut ctx = Context::new(t);
    ctx.initialize()?;
    eprintln!("hello-ca: open hello-rs");
    let sid = ctx.open_session(&Uuid::from_bytes(HELLO_RS_UUID_BYTES), TEEC_LOGIN_PUBLIC)?;
    eprintln!("hello-ca: session {sid}");
    let mut dst = [0u8; 16];
    let n = ctx.invoke_shm(sid, 0, b"hello-rs", &mut dst)?;
    if &dst[..n] != b"hello-rs" {
        return Err(0xFFFF_000Fu32);
    }
    ctx.close_session(sid)?;
    Ok(n)
}
