//! REE RPC daemon. Not TCB.
use rustee_supplicant::Supplicant;
use std::env;
use std::path::PathBuf;

fn main() {
    let root = env::var("RUSTEE_SUPP_ROOT").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from("/var/lib/rustee/supp")
    });
    match Supplicant::new(root) {
        Ok(_) => eprintln!("rustee-supplicant: time+FS+LOAD_TA ready (not TCB)"),
        Err(e) => {
            eprintln!("rustee-supplicant: {e}");
            std::process::exit(1);
        }
    }
}
