# RUSTEE Architecture

Open portable Trusted Execution Environment that implements the GlobalPlatform TEE interfaces.
Trusted OS and TCB in Rust. Isolation is a hardware abstraction layer, not a TrustZone assumption.

Status: architecture locked by RUSTEE Lead Architect (2026-08-25). Implementation follows this document.

## What RUSTEE is (and is not)

RUSTEE is a Trusted OS. It is not a Rust SDK for writing TAs on top of OP-TEE.

Academic RusTEE (ACSAC 2020) and Apache Teaclave TrustZone SDK bind Rust TAs to OP-TEE's C kernel. That leaves the TCB in C. RUSTEE inverts that: the kernel, loader, session dispatcher, crypto, and storage are Rust. TAs may be C (GP ABI) or Rust. The isolation primitive is swappable.

OP-TEE (TF.org, 4.10.0 Apr 2026) already implements Client API v1.0 + Internal Core v1.3.1 and is more portable than the TrustZone stereotype: Arm TZ (primary), RISC-V via OpenSBI dynamic domains + PMP (`plat-virt`), and an Intel-maintained tree mapping OP-TEE onto VT and TDX TDs (vsock/VIRTIO, xtest claimed 100%). The OS is still C. TF.org will not GP-qualify current trees; 2013 qualification was the proprietary predecessor.

The combination that does not exist: (1) GP Client + Internal as the TA/CA ABI, (2) TEE OS TCB in Rust, (3) isolation HAL covering a CI/virt backend and at least one real primitive. Closest pieces: OP-TEE (1+3, C), Teaclave (Rust TAs only), Islet/Salus (Rust monitor, not GP), Open-TEE (userspace CI, C), Suzaki/ta-ref (subset Internal library on SGX/Keystone, not an OS).

RUSTEE makes the HAL the first-class product surface. v0 `virt` is a QEMU/KVM guest (Intel OP-TEE-on-IA pattern: transport + bounce SHM), not Open-TEE process isolation. Open-TEE-style `ci-process` can be a later HAL backend for GDB; it is not a security claim. TAs compile per ISA. No universal TA binary.

License note: optee_os is already BSD-2-Clause. "No GPL in TCB" is a constraint we share, not a differentiator. Apache-2.0 OR MIT is a preference.

## Compliance posture

GlobalPlatform (GPD_SPE_009 TEE System Architecture v1.3) defines a GP TEE as meeting **both**:

1. Functional qualification: TEE Client API + TEE Internal Core API (initial TEE configuration).
2. Security certification: TEE Protection Profile (GPD_SPE_021), Common Criteria, accredited lab.

RUSTEE day-1 claim: **GP interface compatible**, not GP certified.

| Surface | Spec | Version we implement | Notes |
|---|---|---|---|
| System Architecture | GPD_SPE_009 | v1.3 (May 2022) | Requirements, not code |
| Client API | GPD_SPE_007 + GPD_EPR_028 | v1.0 + Errata 2.0 | Frozen. Linux `libteec` / `tee.ko` world. |
| Internal Core API | GPD_SPE_010 | **v1.3.1 first**, v1.4 profile later | OP-TEE and xtest are on 1.3.1. v1.4 (Nov 2025) adds PQC, ChaCha/Poly1305, path identity chains, remote TA-TA. Optional until the 1.3.1 suite is green. |
| Protection Profile | GPD_SPE_021 | v1.3 | Design against isolation/storage properties. Do not claim certification. |
| Sockets / SE / TUI / TEE Mgmt | GPD_SPE_100+ / 024 / TUI | deferred | Not initial configuration. |

Testing path, in order:

1. Our own Rust tests on the `virt` backend (session, invoke, shm, panic, crypto smoke).
2. `optee_test` / xtest against RUSTEE via OP-TEE MSG compatibility (see REE ABI).
3. GP Compliance Test Suite (licensed, later) before any "GP qualified" language.
4. TEE PP / CC only if a product program needs it.

Never market "GP compliant" until (2) is substantially green. Say "implements GPD_SPE_007 and GPD_SPE_010 v1.3.1".

## Layer cake

```
  CA (C or Rust)
       |
       v
  libteec  —  GPD_SPE_007 Client API
       |
       v
  Linux generic TEE  (tee.ko, TEE_IOC_*)
       |
       v
  RUSTEE transport  (v0: OP-TEE MSG compatibility)
       |                 rustee-supplicant for RPC (FS, time, sockets later)
       v
  Isolation HAL     virt | TrustZone | (later: RISC-V CoVE, CCA)
       |
       v
  RUSTEE OS (Rust, no_std)     privileged TEE kernel
       |  session dispatcher, TA loader, threads, MM, RPC
       v
  gp-utee  —  GPD_SPE_010 Internal Core API
       |
       +-- user TAs (C ABI and/or Rust SDK), isolated from kernel and each other
       +-- PTAs (pseudo-TAs) for system services
```

Trust boundary: everything below the isolation HAL is TCB. `tee-supplicant` / `rustee-supplicant` is **not** TCB. REE-backed storage is encrypted and integrity-protected; RPMB (or equivalent anti-rollback) is required before calling that storage "trusted" in the GP sense.

## Decision: portable means a HAL, not ifdefs

`rustee-hal` is a Rust trait crate. Kernel code compiles against the trait. Backends are separate crates.

The HAL must provide:

- World switch / call gate (enter TEE with a message, return a result or RPC)
- Isolated address spaces for TAs (and kernel vs TA)
- Shared memory mapping with explicit REE/TEE permissions
- Entropy source
- Monotonic counter / secure time if the platform has one; otherwise the kernel must not pretend
- Optional: interrupt injection for yielding calls

### Backend order

| Backend | Isolation primitive | When |
|---|---|---|
| `virt` | RUSTEE as a guest (QEMU virt / KVM). VMM is the isolator. | **v0. Required.** CI, bring-up, GP API tests on any host. |
| `tz-aarch64` | ARM TrustZone, RUSTEE at S-EL1, TAs at S-EL0, SMC or FF-A | v1. First hardware. QEMU `virt` + TrustZone or sbsa-ref. |
| `cove-riscv` / `cca` | RISC-V CoVE or Arm CCA realms | later, same HAL |

`virt` is not a toy. It is the portability proof: if Client API + Internal Core API + xtest pass on `virt`, the GP surface is real and the TZ port is "replace the HAL", not "rewrite the OS".

Security caveat: `virt` isolation is only as strong as the VMM and host. Do not call a `virt` build a GP TEE for product. It is the functional and CI target.

## Decision: v0 REE ABI is OP-TEE MSG compatibility

Linux already has `drivers/tee/optee/` speaking OP-TEE MSG over SMCCC or FF-A, plus `optee_client` (`libteec`) and xtest.

v0 RUSTEE implements enough of OP-TEE MSG (`struct optee_msg_arg`, open/invoke/close/shm, RPC for time and FS) that:

- existing `tee.ko` + `libteec` work unchanged on the `tz-aarch64` path
- on `virt`, a thin user-space or virtio transport presents the same MSG ABI to a userspace TEE driver or a small `rustee-virt` Linux driver

v1 native `drivers/tee/rustee/` is allowed once MSG-compat is green. Do not invent a parallel Client API.

Internal OS protocol is **not** OP-TEE. MSG is the REE-facing compatibility shim in `rustee-proto`. Kernel internals stay Rust types.

Identity (frozen):

- MSG ABI / CALLS_UID: OP-TEE API UID `384fb3e0-e7f8-11e3-af63-0002a5d5c51b` (stock `optee.ko` bind on tz-aarch64).
- RUSTEE OS UUID (GET_OS_UUID): `e819d7df-5ffe-45e6-a113-323349b219aa`. Never reuse OP-TEE `486178e0-…`.
- GET_OS_REVISION: 0.1.0.
- virt transport: **vsock + bounce**, not ivshmem. QEMU `vhost-vsock-pci` + `virtio-rng`. Guest CID 3, port 7007, `SOCK_STREAM`. 16 MiB private bounce pool each side. `tmem.buf_ptr` / cookie = **u64 offset**, never host PA or guest GPA. PDU LE: `u32 kind` (ENTER=1, RPC=2, COMPLETE=3, RPC_REPLY=4), `seq`, `arg_len`, `bounce_len`, then 64-byte CallFrame (`arg_len=64`), then bounce. MSG blob is in bounce at cookie a1:a2. Fast SMCCC answered in `rustee-virt.ko` (GPL-2.0-only, not TCB); only yielding calls on vsock. One outstanding call. HAL owns guest vsock/bounce; Client/REE owns host driver, codec, supplicant.
- LOAD_TA RPC is v0 (required for xtest). Caps: DYNAMIC_SHM | UNREGISTERED_SHM | MEMREF_NULL. Thread count 1.


## GP API mapping

### Client API (REE) — implement fully, it is small

- `TEEC_InitializeContext` / `TEEC_FinalizeContext`
- `TEEC_OpenSession` / `TEEC_CloseSession`
- `TEEC_InvokeCommand`
- `TEEC_RegisterSharedMemory` / `TEEC_AllocateSharedMemory` / `TEEC_ReleaseSharedMemory`
- `TEEC_RequestCancellation`
- Parameter types: value, none, memref (temp, whole, partial)
- Origins: TEE, TEEC, TEEC_ORIGIN_*

Host crate: `gp-client` (safe Rust) plus C `libteec` ABI (`tee_client_api.h`, all 10 functions including `TEEC_RequestCancellation`). Reusing `optee_client` as a behavioral stand-in is allowed until our C ABI is bit-identical; do not copy its headers into the RUSTEE tree as the copyright source.

### Internal Core API (TA) — modules, day-1 vs later

TA entry points (mandatory):

- `TA_CreateEntryPoint` / `TA_DestroyEntryPoint`
- `TA_OpenSessionEntryPoint` / `TA_CloseSessionEntryPoint`
- `TA_InvokeCommandEntryPoint`

GPD_SPE_010 v1.3.1 has six modules. OP-TEE's "four major parts" omits Trusted Core Framework and Peripheral/Event. v0 implements 1–5. Peripheral/Event (ch. 9) is deferred with TUI.

Trusted Core Framework (mandatory day-1): panic, property sets (`gpd.ta.*`, `gpd.client.*`, `gpd.tee.*` including `internalCore.version` and time protection levels), memory (`TEE_Malloc`/`Free`/`Realloc`, instance/heap), cancellation, `TEE_CheckMemoryAccessRights`, **TA-to-TA sessions for real** (`TEE_OpenTASession` / `InvokeTACommand` / `CloseTASession`). Do not stub `TEE_ERROR_NOT_SUPPORTED` here; xtest and the 2017 Init Config suite exercise it.

Time API (all five, day-1): `TEE_GetSystemTime`, `TEE_Wait`, `TEE_GetTAPersistentTime`, `TEE_SetTAPersistentTime`, `TEE_GetREETime`. Persistent time may be "needs reset" quality until the HAL has a counter. Advertise the real protection level in properties; do not lie.

Cryptographic Operations API: day-1 = SHALL-set for the frozen Core version, plus `TEE_GenerateRandom` and `TEE_IsAlgorithmSupported`. Practical minimum matching existing TAs: AES (ECB/CBC/CTR/GCM), SHA-2, HMAC, RSA, ECDSA P-256, AES-GCM. Confirm against Table 6-1 of v1.3.1; do not invent the SHALL list. Return `TEE_ERROR_NOT_SUPPORTED` elsewhere. Defer: rest of the 1.3.1 matrix, OP-TEE-only HKDF/PBKDF2/ConcatKDF, 1.4 PQC/ChaCha/RSA-8192.

Trusted Storage: day-1 = private persistent objects + transient objects + data streams (`TEE_STORAGE_PRIVATE`). REE-fs objects encrypted with per-TA keys (AES-GCM) + integrity, keys from a per-device HUK (HAL). Mark as **not anti-rollback** until RPMB or equivalent. Expose rollback properties honestly. `TEE_STORAGE_PERSO` / `PROTECTED` later.

Arithmetical API: **day-1, full GP BigInt + FMM family**. The 2017 Init Config suite (still the active GP functional kit) and OP-TEE xtest exercise it. v1.4 deprecates section 8; keep it behind a feature flag when we take the 1.4 profile.

Peripheral and Event APIs (v1.2+): deferred.

Internal Core v1.4 extras (path identity, remote TA-TA, PQC, panic masking `_PS`, KEM encapsulate): compile-time profile `gp-1.4`, off by default. Do not claim v1.4 until a test suite exists.

C ABI: independently written `tee_client_api.h` and `tee_internal_api.h` from GP identifier tables, RUSTEE license, comment `implements GPD_SPE_xxx vY`. Do not paste GP spec prose or copy OP-TEE headers as the copyright source. Behavioral oracle = OP-TEE headers + xtest, not a copy. Rust TAs use `rustee-utee` (safe wrappers). Header name for Client API MUST be `tee_client_api.h`. `TEEC_CONFIG_PAYLOAD_REF_COUNT` = 4. `TEEC_CONFIG_SHAREDMEM_MAX_SIZE` >= 512 KiB.

## TA model

- User TAs are unprivileged relative to RUSTEE OS. They cannot map other TAs or kernel.
- Load format: ELF with section `.rustee.ta_head`, magic RTAH `0x48415452`, 40-byte LE named GP fields (uuid, stack_size, data_size, single_instance, multi_session, instance_keep_alive, endian=0, ta_version). Optional UTF-8 trailer for description/version. Not an OP-TEE `TA_FLAGS` bitfield. Entry points remain GP symbols: `TA_CreateEntryPoint` / `TA_DestroyEntryPoint` / `TA_OpenSessionEntryPoint` / `TA_CloseSessionEntryPoint` / `TA_InvokeCommandEntryPoint`.
- Signed load envelope `RTSG` + RSA-PKCS1-v1.5-SHA256 with compiled-in v0 dev key, verified via CryptoProvider (no RSA in rustee-os). Early TAs skip envelope, still have `.rustee.ta_head`.
- Multi-session: yes, matching GP. Instance keep-alive vs create-on-session as named header fields.
- Panic: panicking TA dies; kernel does not. Session returns `TEE_ERROR_TARGET_DEAD`.
- PTA: linked with the kernel, UUID-routed, used for system services (not GP-portable). Keep the PTA surface small.

## Crypto and storage

Crypto lives in `rustee-crypto`. Default software: audited Rust crates (`aes-gcm`, `sha2`, `hmac`, `p256`, `rsa`, `rand_core`) behind a `CryptoProvider` trait so a platform can swap in CAAM/TrustZone crypto or a future PSA Crypto. No mbedTLS in the TCB unless a platform HAL explicitly vendors it.

Suzaki/TrustCom 2020 split (keep it): Independent Internal APIs (bulk crypto, objects, sessions) live once in rustee-utee/rustee-crypto. Backend-dependent Internal APIs (storage, time, RNG, TEE_GenerateKey/HUK) are HAL/platform traits. That is the real portability surface, not a universal TA binary.

HUK and TRNG come from the HAL. If a backend has no TRNG, `virt` may use virtio-rng or host getrandom and **must** log that entropy is REE-sourced.

Secure storage: `rustee-storage` with two backends:

1. `ree-fs` via RPC to supplicant (encrypted objects). Development and `virt`.
2. `rpmb` when the HAL exposes it. Required before GP trusted-storage claims.

## License and TCB policy

- RUSTEE OS, HAL, proto, utee, crypto, storage: **Apache-2.0 OR MIT**
- Linux kernel driver: **GPL-2.0-only** (cannot be otherwise)
- No GPL code in the TEE TCB
- GP spec text is not redistributed; we implement from the public specs. Header constants/names are as specified.

## Repository layout

Monorepo `rustee`:

```
docs/architecture.md          this file
crates/
  rustee-hal/                 Isolation traits
  rustee-hal-virt/
  rustee-hal-tz/              (stub until v1)
  rustee-proto/               OP-TEE MSG compatibility + native types
  rustee-os/                  kernel
  rustee-utee/                Internal Core API runtime (TA side)
  rustee-crypto/
  rustee-storage/
  gp-client/                  Client API (host)
host/
  rustee-supplicant/
  rustee-linux/               virt driver notes / out-of-tree module
ta/
  hello/                      GP C ABI example
  hello-rs/                   Rust TA example
tests/
  smoke/                      Rust tests on virt
  xtest-notes.md              which xtest cases we track
```

Workspace: Cargo. Kernel is `no_std`. Host tools are `std`.

## v0 milestone (definition of done)

A CA on the host, using Client API, opens a session to a hello TA running in RUSTEE on QEMU `virt`, invokes a command with a shared buffer, gets a correct result, closes. Kernel and TA are Rust. Panic of the TA does not take down the OS.

Then: AES-GCM + SHA-256 TA, REE-fs storage smoke, and a tracked xtest subset.

## Explicit non-goals (v0)

- GP certification / TEE PP evaluation
- Trusted User Interface, Sockets API, SE API
- Multi-TEE / OP-TEE SPMC / FF-A SP
- Android Binder/Trusty IPC
- Making OP-TEE itself Rust
- Replacing Teaclave as a TA SDK (we will offer `rustee-utee`; that is not the product)

## Engineering ownership

| Domain | Owner agent | First job |
|---|---|---|
| Isolation HAL + virt backend | HAL Engineer | `rustee-hal` traits + `rustee-hal-virt` QEMU guest that can enter/exit with a message |
| Trusted OS kernel | Kernel Engineer | `no_std` kernel: panic, heap, thread, session table, TA ELF stub loader |
| GP Internal Core / TA runtime | Internal API Engineer | TA entry points, params, panic, malloc; C header + `rustee-utee` |
| GP Client API + Linux/REE | Client/REE Engineer | `gp-client` + MSG shim + supplicant RPC loop; virt transport to the guest |
| Crypto + secure storage | Crypto/Storage Engineer | `CryptoProvider` + AES/SHA/HMAC/P-256; `ree-fs` encrypted objects |

Cross-cutting (Lead Architect): API freeze, MSG compatibility scope, when to say "GP", repo layout, backend order.
