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
RUSTEE_SUPP_ROOT=/tmp/rustee-supp cargo run -p rustee-smoke --bin hello-ca
```

`hello-ca` opens hello-rs, invokes cmd 0 (memref 0 → 1), checks the shm copy of `hello-rs`.
