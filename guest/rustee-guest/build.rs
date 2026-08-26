fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rerun-if-changed=link.ld");
    println!("cargo:rustc-link-search=native={dir}");
    // Single -T. Do not also pass -Tlink.ld via .cargo/config.toml rustflags.
    println!("cargo:rustc-link-arg=-T{dir}/link.ld");
}
