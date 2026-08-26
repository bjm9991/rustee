# v0 QEMU virt

Guest is `aarch64-unknown-none` EL1. Not `virt,secure=on`. Isolation is the VMM.

Host Linux needs `vhost_vsock`. Guest CID **3**, port **7007**, `SOCK_STREAM`.
`rustee-virt.ko` / `hello-ca` `kernel_connect`s; virtio REQUEST/RESPONSE is vhost.
Entropy is `virtio-rng` (REE-sourced). No ivshmem.

Build the guest ELF (HAL `init` binds CID 3:7007 + virtio-rng):

```
cargo build -p rustee-guest --target aarch64-unknown-none --features boot
```

```
sudo modprobe vhost_vsock
host/run-qemu.sh target/aarch64-unknown-none/debug/rustee-guest
```

Then:

```
RUSTEE_HELLO_TA=/path/to/hello-rs.ta \
RUSTEE_SUPP_ROOT=/tmp/rustee-supp \
  cargo run -p rustee-smoke --bin hello-ca
```

`hello-ca` stages `$RUSTEE_SUPP_ROOT/ta/8d825f6a1c4b4c9f9e3a2b7c6d5e4f30.ta` (copy from `RUSTEE_HELLO_TA` if the file is missing), opens hello-rs, invokes cmd 0 (memref 0 → 1), checks the shm copy of `hello-rs`.

OpenSession yields `LOAD_TA`. Guest packs it at bounce cookie `0x80_0000`, param 1 `TMEM_OUTPUT` dest cookie+96, cap 2 MiB. The supplicant copies the ELF at `params[1].a` (pool offset, not a VA) and RPC_REPLY `bounce_len` covers dest plus the ELF. `rustee-virt.ko` still does not answer `KIND_RPC`; v0 live path is userspace `StreamTransport`.
