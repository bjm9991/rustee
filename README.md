# RUSTEE

Open portable Trusted Execution Environment. A **Rust Trusted OS** that implements the GlobalPlatform TEE Client API (`GPD_SPE_007` v1.0 + `GPD_EPR_028`) and Internal Core API (`GPD_SPE_010` v1.3.1). Isolation is a HAL.

This is **not** a TA SDK on OP-TEE (that is ACSAC 2020 RusTEE / Apache Teaclave TrustZone SDK). Day-1 claim is GP *interface compatible*, not GP certified.

## v0 done

A CA using the Client API opens a session to a Rust hello TA running in RUSTEE on QEMU/KVM virt, invokes with shared memory, gets the right answer, and a TA panic does not kill the OS.

v0 virt transport: `vhost-vsock-pci` + bounce buffers (not ivshmem). Guest crate target: `aarch64-unknown-none`.

## Crates

| Crate | Role |
|---|---|
| `rustee-hal` | Isolation traits (`Hal`, `CallGate`, …) |
| `rustee-hal-virt` | QEMU/KVM vsock + bounce backend |
| `rustee-hal-tz` | TrustZone stub |
| `rustee-proto` | OP-TEE MSG compatibility (REE shim only) |
| `rustee-os` | Privileged TEE kernel |
| `rustee-utee` | Internal Core API / TA runtime |
| `rustee-crypto` | `CryptoProvider` + arith |
| `rustee-storage` | ree-fs (not GP trusted storage) |
| `gp-client` | Host Client API |
| `rustee-supplicant` | REE RPC daemon (not TCB) |

License: Apache-2.0 OR MIT. A future `rustee-virt.ko` Linux driver would be GPL-2.0-only and is not in the TCB.

See [docs/architecture.md](docs/architecture.md).
