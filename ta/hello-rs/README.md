# hello-rs

v0 echo TA. UUID `8d825f6a-1c4b-4c9f-9e3a-2b7c6d5e4f30`.
Cmd 0 copies memref 0 → 1 (`Params::copy_memref`; TA VAs, not cookies).

## Host tests

```
cargo test -p hello-rs
```

Crate type is `lib` + `staticlib`. Host tests use the rlib.

## Loadable aarch64 ELF (`.ta`)

Raw ELF64 LE. **Not** an RTSG envelope (kernel `load_image` accepts RTSG *or* raw ELF with `.rustee.ta_head`; crt0 does not emit RTSG).

```
rustup target add aarch64-unknown-none   # once
./ta/hello-rs/build-ta.sh                # release -> target/hello-rs.ta
```

Equivalent:

```
cargo build -p hello-rs --target aarch64-unknown-none --release
# then ld/rust-lld -T ta/hello-rs/link.ld (KEEP .rustee.ta_head) on
# target/aarch64-unknown-none/release/libhello_rs.a
```

`#[used]` + `link.ld` `KEEP(*(.rustee.ta_head))` keep the 40-byte RTAH section.
Exported C symbols: `TA_CreateEntryPoint`, `TA_DestroyEntryPoint`,
`TA_OpenSessionEntryPoint`, `TA_CloseSessionEntryPoint`, `TA_InvokeCommandEntryPoint`.

Panic is `abort`. Target flags match the guest (`aarch64-unknown-none`, `-C panic=abort`).

Client/QEMU smoke:

```
RUSTEE_HELLO_TA=$PWD/target/hello-rs.ta \
RUSTEE_SUPP_ROOT=/tmp/rustee-supp \
  cargo run -p rustee-smoke --bin hello-ca
```

Supplicant stages `$RUSTEE_SUPP_ROOT/ta/8d825f6a1c4b4c9f9e3a2b7c6d5e4f30.ta`.
