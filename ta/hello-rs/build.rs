fn main() {
    println!("cargo:rerun-if-changed=link.ld");
    println!("cargo:rerun-if-changed=build-ta.sh");
    let target = std::env::var("TARGET").unwrap_or_default();
    if target == "aarch64-unknown-none" {
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        println!("cargo:rustc-link-search=native={dir}");
        println!("cargo:rustc-link-arg=-T{dir}/link.ld");
    }
}
