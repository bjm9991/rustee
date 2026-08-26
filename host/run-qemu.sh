#!/bin/sh
# v0 virt: vhost-vsock-pci guest-cid=3 + virtio-rng. Not secure=on, not ivshmem.
set -e
KERNEL=${1:?usage: host/run-qemu.sh <guest-elf>}
modprobe vhost_vsock 2>/dev/null || true
exec qemu-system-aarch64 \
  -machine virt \
  -cpu max \
  -m 256M \
  -smp 1 \
  -nographic \
  -device vhost-vsock-pci,guest-cid=3 \
  -device virtio-rng-pci \
  -kernel "$KERNEL"
