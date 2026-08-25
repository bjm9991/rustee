# v0 QEMU virt

Guest is `aarch64-unknown-none` EL1. Not `virt,secure=on`. Isolation is the VMM.

Host Linux needs `vhost_vsock`. Guest CID **3**, port **7007**, `SOCK_STREAM`.
`rustee-virt.ko` / `hello-ca` `kernel_connect`s; virtio REQUEST/RESPONSE is vhost.
Entropy is `virtio-rng` (REE-sourced). No ivshmem.

```
sudo modprobe vhost_vsock

qemu-system-aarch64 \
  -machine virt \
  -cpu max \
  -m 256M \
  -smp 1 \
  -nographic \
  -device vhost-vsock-pci,guest-cid=3 \
  -device virtio-rng-pci \
  -kernel "$RUSTEE_GUEST_ELF"
```

`$RUSTEE_GUEST_ELF` is the HAL/kernel image (binds CID 3:7007 at `Hal::init`). Then:

```
RUSTEE_SUPP_ROOT=/tmp/rustee-supp cargo run -p rustee-smoke --bin hello-ca
```

`hello-ca` opens hello-rs, invokes cmd 0 (memref 0 → 1), checks the shm copy of `hello-rs`.
