# rustee-crypto and rustee-storage (day-1)

Owner: RUSTEE Crypto Engineer.
Status: FROZEN by Lead Architect 2026-08-25 (locks below). Origin repo not minted. Sketch only.
Follows docs/architecture.md. Apache-2.0 OR MIT. no_std + alloc. No GPL in TCB.

This is the primitive layer. rustee-utee owns TEE_* names, TEE_AllocateOperation,
and Init/Update/DoFinal buffering. rustee-hal owns Entropy and Huk. rustee-proto /
rustee-supplicant own MSG RPC command numbers.

---

## 1. rustee-crypto

### 1.1 Crate split

- `rustee-crypto`: `CryptoProvider` trait, algorithm/key types, `SoftwareProvider`.
- Depends on HAL traits for entropy and HUK; never calls getrandom itself.
- Default software (RustCrypto, dual-licensed MIT/Apache-2.0): `aes`, `aes-gcm`,
  `cbc`, `ctr`, `sha2`, `hmac`, `rsa`, `p256`, `hkdf`, `rand_core`, `zeroize`.
- No mbedTLS, no `ring` unless a later decision. No GP Internal API types here.

### 1.2 HAL surface this crate consumes (owned by HAL Engineer)

```rust
/// Entropy never originates in rustee-crypto.
pub trait Entropy {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), HalError>;
    fn origin(&self) -> EntropyOrigin;
}

pub enum EntropyOrigin {
    /// TRNG / HW RNG inside the isolation boundary.
    Isolated,
    /// virtio-rng or host getrandom. Entropy is REE-sourced.
    /// Not a product TEE RNG. virt must return this.
    ReeHost,
}

/// Per-device hardware unique key. Bytes never leave the TEE.
pub trait Huk {
    /// At least 32 bytes. Lifetime of the device image.
    /// virt: provisioned development HUK, never all-zero, not a secret.
    fn material(&self) -> &[u8];
}
```

Boot policy: constructing a provider with `EntropyOrigin::ReeHost` requires
feature `allow-ree-entropy` and MUST log
`RUSTEE entropy is REE-sourced (virt/host); not a product TEE RNG`.
virt HUK is a compile-time test key behind `allow-ree-huk` and MUST log
`RUSTEE HUK is a development test key; not a product HUK`.
`tz-aarch64` enables neither feature. Crypto never calls getrandom.

HKDF-SHA256 is crate-internal (storage key derivation). Not a GP algorithm
until Internal Core HKDF is scheduled. Architecture defers OP-TEE HKDF
extensions on the utee surface.

### 1.3 Day-1 algorithms (closed set)

| Primitive | Day-1 | Notes |
|---|---|---|
| AES-ECB-NOPAD | 128/256 | 192 deferred |
| AES-CBC-NOPAD | 128/256 | caller supplies IV |
| AES-CTR | 128/256 | |
| AES-GCM | 128/256 | 96-bit nonce only; 128-bit tag |
| SHA-1 | yes | 2017 Init Config / xtest |
| SHA-256 | yes | incremental |
| HMAC-SHA1 | yes | 2017 Init Config / xtest |
| HMAC-SHA256 | yes | incremental |
| RSA 2048/3072 | sign PSS-SHA256, sign PKCS1-v1.5-SHA256, OAEP-SHA256 | 1024 rejected; PKCS1-v1.5 encrypt OUT |
| ECDSA P-256 SHA-256 | yes | IEEE P1363 (r\|\|s) internally; utee maps to GP |
| TRNG | HAL | |
| SHA-224/384/512, AES-192, AES-CCM, AES-CTS/XTS/CMAC, RSA-NOPAD, PKCS1-v1.5 encrypt, ECDH, GP HKDF, DES, MD5, SHA-3, DSA, DH, PQC | no | hard error |

Provider returns a typed `Unsupported` for anything else. Do not silently
downgrade.

### 1.4 `CryptoProvider` trait

One-shot at the provider (matches `aes-gcm`). Hash/HMAC are incremental.
utee buffers Cipher/AE Init/Update/DoFinal and calls these at Final.
Hardware providers can later add streaming associated types without
breaking one-shot methods.

```rust
#![no_std]
extern crate alloc;

pub struct AesKey { bits: AesBits, bytes: AesKeyBytes } // zeroize on drop
pub enum AesBits { Aes128, Aes256 }

pub struct RsaPublic { n_bits: RsaBits, n: alloc::vec::Vec<u8>, e: alloc::vec::Vec<u8> }
pub struct RsaPrivate { /* zeroize on drop; 2048 or 3072 only */ }
pub enum RsaBits { Rsa2048, Rsa3072 }

pub struct P256Public([u8; 65]);  // uncompressed SEC1
pub struct P256Secret([u8; 32]);  // zeroize on drop

#[non_exhaustive]
pub enum CryptoError {
    Unsupported,
    InvalidLength,
    InvalidNonce,
    AuthFailure,          // GCM tag / RSA-OAEP / verify fail; fail closed
    KeyRejected,
    Entropy,
    ReeEntropyNotAllowed,
    ReeHukNotAllowed,
}

pub trait Sha256Op {
    fn update(&mut self, data: &[u8]);
    fn finalize_into(self, out: &mut [u8; 32]);
}

pub trait HmacSha256Op {
    fn update(&mut self, data: &[u8]);
    fn finalize_into(self, out: &mut [u8; 32]);
}

pub trait CryptoProvider {
    type Sha256: Sha256Op;
    type HmacSha256: HmacSha256Op;

    fn sha256(&self) -> Self::Sha256;
    fn hmac_sha256(&self, key: &[u8]) -> Result<Self::HmacSha256, CryptoError>;

    fn aes_ecb_encrypt(&self, key: &AesKey, pt: &[u8], ct: &mut [u8]) -> Result<(), CryptoError>;
    fn aes_ecb_decrypt(&self, key: &AesKey, ct: &[u8], pt: &mut [u8]) -> Result<(), CryptoError>;
    fn aes_cbc_encrypt(&self, key: &AesKey, iv: &[u8; 16], pt: &[u8], ct: &mut [u8]) -> Result<(), CryptoError>;
    fn aes_cbc_decrypt(&self, key: &AesKey, iv: &[u8; 16], ct: &[u8], pt: &mut [u8]) -> Result<(), CryptoError>;
    fn aes_ctr(&self, key: &AesKey, iv: &[u8; 16], inout: &mut [u8]) -> Result<(), CryptoError>;

    /// nonce MUST be unique per (key, message). 96-bit only on day-1.
    fn aes_gcm_encrypt(
        &self,
        key: &AesKey,
        nonce: &[u8; 12],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), CryptoError>;
    fn aes_gcm_decrypt(
        &self,
        key: &AesKey,
        nonce: &[u8; 12],
        aad: &[u8],
        ct: &[u8],
        tag: &[u8; 16],
        pt: &mut [u8],
    ) -> Result<(), CryptoError>; // AuthFailure on mismatch; no partial pt

    fn rsa_oaep_encrypt(&self, pk: &RsaPublic, pt: &[u8], ct: &mut [u8]) -> Result<usize, CryptoError>;
    fn rsa_oaep_decrypt(&self, sk: &RsaPrivate, ct: &[u8], pt: &mut [u8]) -> Result<usize, CryptoError>;
    fn rsa_pss_sign(&self, sk: &RsaPrivate, digest: &[u8; 32], sig: &mut [u8]) -> Result<usize, CryptoError>;
    fn rsa_pss_verify(&self, pk: &RsaPublic, digest: &[u8; 32], sig: &[u8]) -> Result<(), CryptoError>;
    fn rsa_pkcs1_sign(&self, sk: &RsaPrivate, digest: &[u8; 32], sig: &mut [u8]) -> Result<usize, CryptoError>;
    fn rsa_pkcs1_verify(&self, pk: &RsaPublic, digest: &[u8; 32], sig: &[u8]) -> Result<(), CryptoError>;

    fn ecdsa_p256_sign(&self, sk: &P256Secret, digest: &[u8; 32], sig: &mut [u8; 64]) -> Result<(), CryptoError>;
    fn ecdsa_p256_verify(&self, pk: &P256Public, digest: &[u8; 32], sig: &[u8; 64]) -> Result<(), CryptoError>;

    fn generate_aes(&self, bits: AesBits, rng: &mut impl Entropy) -> Result<AesKey, CryptoError>;
    fn generate_rsa(&self, bits: RsaBits, rng: &mut impl Entropy) -> Result<(RsaPublic, RsaPrivate), CryptoError>;
    fn generate_p256(&self, rng: &mut impl Entropy) -> Result<(P256Public, P256Secret), CryptoError>;
}

/// Default. Swap for CAAM / TZ crypto / PSA later via the same trait.
pub struct SoftwareProvider;
```

`SoftwareProvider` is the v0 impl. Kernel is generic: `Kernel<H: Hal, C: CryptoProvider>`.

PKCS1-v1.5 **encryption** is not day-1 (architecture named OAEP). PKCS1-v1.5
**signature** is included because xtest and existing TAs use
`TEE_ALG_RSASSA_PKCS1_V1_5_SHA256`.

---

## 2. rustee-storage (ree-fs)

### 2.1 Claim

Day-1 backend is **encrypted REE-fs**, not GP trusted storage.

- Confidentiality: AES-256-GCM on object bodies.
- Integrity: HMAC-SHA256 over the per-TA directory (binds object ids, file ids,
  sizes, GCM tags, per-object versions).
- **Not anti-rollback.** REE (supplicant, host fs) can delete files or restore
  older versions. No RPMB / monotonic counter on virt.
- rustee-supplicant is **not TCB**. Ciphertext and HMAC are the only protection.
- Not GP trusted storage and not anti-rollback.
  Internal API still exposes `TEE_STORAGE_PRIVATE` as the storage ID (TAs call
  that) with honest rollback properties. Architecture language stays encrypted
  REE-fs until RPMB exists.

Second backend `rpmb` (HAL) is required before any GP trusted-storage claim.
Format leaves a `dir_generation` field to bind into RPMB later without a
layout break.

### 2.2 Key hierarchy

All HKDF-SHA256, extract-then-expand, IKM = parent key, salt empty,
info as below. Keys zeroized on drop. HUK bytes never written to REE.

```
HUK                         HAL, >= 32 bytes
  |
  HKDF(HUK,  info = "rustee.storage.ssk.v1")
  = SSK                     32-byte device storage master
  |
  HKDF(SSK,  info = "rustee.storage.ta.v1" || ta_uuid)
  = TSK                     32-byte per-TA key
  |
  +-- HKDF(TSK, info = "rustee.storage.wrap.v1")  = K_wrap   AES-256-GCM wrap key
  +-- HKDF(TSK, info = "rustee.storage.dir.v1")   = K_dir    AES-256-GCM directory
  +-- HKDF(TSK, info = "rustee.storage.mac.v1")   = K_mac    HMAC-SHA256 directory
```

Each object gets a random 32-byte FEK from HAL entropy at create. FEK is
wrapped under `K_wrap` (AES-256-GCM) and stored in the object header.
Object body is AES-256-GCM under FEK. Unique 96-bit nonce per wrap and per
body, stored in the header, generated from HAL entropy. Fail closed on
nonce-generation failure.

### 2.3 On-disk layout (what the supplicant stores)

GP object IDs are up to 64 bytes and may be secret. They do **not** appear
in filenames.

```
<tee-root>/                          # supplicant-chosen root, e.g. /data/tee
  <ta_uuid_hex>/                     # UUID is public TA identity
    dir.v1                           # encrypted directory + HMAC trailer
    obj/<file_id_hex>                # 16-byte random file_id
```

`file_id` is a 128-bit random id, not a function of objectId.

#### `dir.v1` file

```
[dir_ciphertext || dir_gcm_tag(16)] || hmac_sha256(K_mac, dir_ciphertext || tag)[32]
```

Directory plaintext (AES-256-GCM under `K_dir`, nonce in first 12 bytes of the
file before ciphertext, AAD = `b"RSTE-dir-v1" || ta_uuid`):

```
magic          [u8; 4]   b"RSTD"
version        u8        1
reserved       [u8; 3]   0
dir_generation u64       monotonic; bind to RPMB later; increment on every dir write
entry_count    u32
entries[] {
  file_id      [u8; 16]
  oid_hash     [u8; 32]  SHA-256(gp_object_id)  // lookup only; id lives inside object
  flags        u32       GP usage flags
  data_size    u64
  obj_version  u64       per-object generation
  gcm_tag      [u8; 16]  object body tag, binds directory to file contents
}
```

HMAC is redundant with directory GCM **on purpose**: later the HMAC (or a
truncation) is what we write into RPMB as the rollback root, without
re-encrypting objects.

Lookup: SHA-256(objectId) vs `oid_hash`. Enumeration walks entries.

#### Object file `obj/<file_id>`

```
offset  size  field
0       4     magic b"RSTO"
4       1     version = 1
5       1     flags (bit0 reserved: anti-rollback bound)
6       2     reserved = 0
8       16    file_id
24      16    ta_uuid
40      8     obj_version (must match dir entry)
48      12    wrap_nonce
60      12    body_nonce
72      48    wrapped_fek  (32-byte FEK ciphertext + 16-byte tag)
120     8     pt_len
128     N     body ciphertext (length pt_len)
128+N   16    body_tag
```

Wrap AAD: `magic || version || ta_uuid || file_id || obj_version`.
Body AAD: `magic || version || ta_uuid || file_id || obj_version || pt_len`.

Inner plaintext:

```
oid_len     u8
oid         [u8; oid_len]      // the GP objectId, confidential
data        [u8; pt_len-1-oid_len]
```

Day-1: whole-object read/write, max 1 MiB payload. Seek/truncate are
supported in-memory on the loaded object. Block/hash-tree (version 2) can
split `data` later without changing the header prefix.

Create/write always: new FEK or same FEK with **new** body_nonce, new
obj_version, rewrite dir.v1 (new dir_generation, new HMAC).

### 2.4 Threats this does and does not cover

| REE action | Day-1 result |
|---|---|---|
| Read files | ciphertext only |
| Bit-flip object or dir | GCM or HMAC fail, object/dir rejected |
| Swap two objects in the same TA | file_id / AAD / dir HMAC fail |
| Swap objects across TAs | TSK mismatch, unwrap fail |
| Delete an object / dir | silent loss; no GP trusted-storage guarantee |
| Restore an older dir.v1 + objects | silent rollback; dir_generation not checked until RPMB |

### 2.5 FS RPC this crate needs (Client/REE + proto)

Semantic ops. Command IDs belong to rustee-proto MSG shim.

```
fs.create(path, data) -> Result
fs.read(path) -> Result<Vec<u8>>
fs.write(path, data) -> Result          // overwrite
fs.delete(path) -> Result
fs.rename(from, to) -> Result
fs.mkdir(path) -> Result
```

Paths are relative to the TA dir. No directory listing required on day-1
(we keep the index in `dir.v1`). Supplicant must not interpret file
contents. Partial/failed write: storage treats missing or short files as
corrupt, not as truncated objects.

### 2.6 Public storage crate API (kernel-facing)

```rust
pub enum StorageClass {
    /// Encrypted REE-fs. Not anti-rollback. Not GP trusted storage.
    ReeFsEncrypted,
    // Rpmb  — later
}

pub struct ReeFs<C: CryptoProvider, E: Entropy, H: Huk, Rpc: FsRpc> { ... }

impl<...> ReeFs<...> {
    pub fn create(&mut self, ta: Uuid, object_id: &[u8], flags: u32, data: &[u8]) -> Result<ObjectHandle, StorageError>;
    pub fn open(&mut self, ta: Uuid, object_id: &[u8]) -> Result<ObjectHandle, StorageError>;
    pub fn read(&mut self, h: &ObjectHandle, off: u64, buf: &mut [u8]) -> Result<usize, StorageError>;
    pub fn write(&mut self, h: &mut ObjectHandle, off: u64, buf: &[u8]) -> Result<usize, StorageError>;
    pub fn truncate(&mut self, h: &mut ObjectHandle, size: u64) -> Result<(), StorageError>;
    pub fn delete(&mut self, ta: Uuid, object_id: &[u8]) -> Result<(), StorageError>;
    pub fn rename(&mut self, ta: Uuid, old: &[u8], new: &[u8]) -> Result<(), StorageError>;
}
```

`StorageError::Corrupt` on auth failure. No distinction leaked to TAs
beyond GP `TEE_ERROR_CORRUPT_OBJECT` / `TEE_ERROR_ITEM_NOT_FOUND` mapping
in utee.

---

## 3. Out of scope until asked

- Full GPD_SPE_010 1.3.1 algorithm matrix
- GPD_SPE_010 1.4 PQC / ChaCha-Poly
- RPMB backend
- Hash-tree / 4 KiB block files
- mbedTLS
- Implementing in the Origin repo (waiting on URL)

---

---

## Freeze locks (Lead Architect 2026-08-25) — authoritative over earlier SHALL-set notes

Day-1 IN:
AES-ECB/CBC/CTR/GCM (128/256), SHA-1, SHA-256, HMAC-SHA1, HMAC-SHA256,
RSA 2048/3072 PSS-SHA256 + PKCS1-v1.5-SHA256 sign/verify + OAEP-SHA256,
ECDSA P-256, TEE_GenerateRandom, TEE_IsAlgorithmSupported, full ch.8 Arith.

Day-1 OUT (Unsupported, hard error, no silent downgrade):
PKCS1-v1.5 encrypt, SHA-224/384/512, AES-192, AES-CCM, RSA-NOPAD, ECDH,
GP-surface HKDF, DES/3DES, MD5, SHA-3, DSA, DH, AES-CTS/XTS/CMAC,
other ECC/Ed/SM, 1.4 PQC.

HKDF-SHA256 crate-internal for SSK/TSK only.
virt: allow-ree-entropy + allow-ree-huk, both logged, not product.
ree-fs: 1 MiB whole-object; TEE_STORAGE_PRIVATE id with honest no-anti-rollback.
Stay on this sketch until Origin URL lands.


## Superseded Table 6-11 note (do not implement as day-1)

Originally confirmed Table 6-11 unstarred as SHALL. Architect then locked the narrower set above. That note is historical.

## Freeze correction (2026-08-25, Lead Architect)

Day-1 is the SHALL-set of GPD_SPE_010 v1.3.1, confirmed from the public spec
(GPD_TEE_Internal_Core_API_Specification_v1.3.1_PublicRelease_CC.pdf), not an
invented subset.

Identifier-level rule (section 6.10.1, after Table 6-11):
"Algorithms flagged * are required in limited circumstances, as discussed in
Table 6-2. For all other algorithms listed in Table 6-11, support is mandatory."

Table 6-1 is the family view of that mandatory set. Table 6-2 is optional ECC/SM.

### SHALL (unstarred Table 6-11)

Digests: MD5, SHA-1, SHA-224/256/384/512, SHA3-224/256/384/512, SHAKE128/256
AES: ECB_NOPAD, CBC_NOPAD, CTR, CTS, XTS, CBC_MAC_NOPAD, CBC_MAC_PKCS5, CMAC, CCM, GCM
DES and 3DES: ECB_NOPAD, CBC_NOPAD, CBC_MAC_NOPAD, CBC_MAC_PKCS5
HMAC: MD5, SHA-1, SHA-224/256/384/512, SHA3-224/256/384/512
RSA: PKCS1-v1.5 sign (MD5, SHA-1, SHA-2, SHA-3), PSS MGF1 (SHA-1, SHA-2, SHA-3),
     PKCS1-v1.5 encrypt, OAEP MGF1 SHA-1/224/256/384/512, RSA_NOPAD
     (6.7.1: SHA-3 OAEP variants are explicitly optional)
DSA: SHA1, SHA224, SHA256, SHA3-224/256/384/512
DH: TEE_ALG_DH_DERIVE_SHARED_SECRET
HKDF: TEE_ALG_HKDF is unstarred in Table 6-11 (GP, not OP-TEE-only)
Key sizes: AES 128/192/256; RSA 256, 512, 768, 1024, 1536, 2048, 3072, 4096 (Table 5-9)

### Optional (starred / Table 6-2) — NOT_SUPPORTED except P-256

ECDSA, ECDH, Ed25519, Ed448, X25519, X448, SM2, SM3, SM4.
Exception named by architect: ECDSA P-256 (TEE_ALG_ECDSA_SHA256 + TEE_ECC_CURVE_NIST_P256).

### Also day-1

TEE_GenerateRandom (HAL entropy, ReeHost logged on virt)
TEE_IsAlgorithmSupported (truthful; never panics)
Full chapter 8 Arithmetical API: BigInt + FMM, M >= 2048 (we implement 4096 to match RSA-4096)

### Not day-1

OP-TEE-only PBKDF2 / ConcatKDF / extra HKDF modes
1.4 PQC, ChaCha-Poly, remaining curves
Anything reserved / TEE_ALG_ILLEGAL_VALUE

### Land order

Practical minimum first (v0 smoke): AES ECB/CBC/CTR/GCM, SHA-2, HMAC-SHA-2, RSA, ECDSA P-256,
GenerateRandom, IsAlgorithmSupported.
Rest of unstarred Table 6-11 is still 1.3.1 SHALL, implemented next, not a later spec version.

### Arith ownership

rustee-crypto: limb math, FMM, gcd, expmod, probable prime. no_std.
rustee-utee: TEE_BigInt* C ABI, SizeInU32, TA-allocated storage, panic policy,
gpd.tee.arith.maxBigIntSize.

---

## 4. rustee-crypto::arith (GPD_SPE_010 ch.8)

Owner: Crypto Engineer. utee thin-forwards TEE_* symbols.
Crate: module in rustee-crypto, not rustee-arith. no_std.
Feature `arith` default-on for 1.3.1; later gp-1.4 profile turns it off (deprecated).
Day-1, not a stub. Required for 1.3.1 / 2017 Init Config / xtest.

Layout: TEE_BigInt is uint32_t[TEE_BigIntSizeInU32(n)] with
TEE_BigIntSizeInU32(n) = ((((n)+31)/32)+2) (spec macro, in utee header).
Internal metadata occupies the extra 2 words. FMM is Montgomery.
maxBigIntSize = 4096.

Surface (utee passes TA allocations as u32 slices):
init, init_fmm_context1, init_fmm,
fmm_context_size_in_u32, fmm_size_in_u32,
from/to_octet_string, from/to_s32,
cmp, cmp_s32, shift_right, get_bit, get_bit_count, set_bit, assign, abs,
add, sub, neg, mul, square, div,
mod, add_mod, sub_mod, mul_mod, square_mod, inv_mod, exp_mod,
relative_prime, compute_extended_gcd, is_probable_prime,
convert_to/from_fmm, compute_fmm.

## Smoke vs 1.3.1 backlog (Lead Architect 2026-08-25)

Table 6-11 unstarred is 1.3.1 SHALL. v0 smoke is the practical minimum only.
is_supported is truthful to what SoftwareProvider has coded. Backlog algs
flip true as they land. Never claim Internal Core 1.3.1 complete until green.
SHA-3 OAEP stays NOT_SUPPORTED. Starred ECC/Ed/SM NOT_SUPPORTED except P-256.


## Enumerator (locked with Internal API)

utee buffers Cipher/MAC/AE; rustee-crypto AES/GCM stays one-shot. GCM 12/16 only.

ReeFs::list(ta) -> Vec<ObjectMeta { object_id, flags, data_size }> for
TEE_StartPersistentObjectEnumerator. dir.v1 entries store oid_len+oid inside
the encrypted directory (not only sha256(oid)). Filenames remain random file_id.
StorageError::TooBig for >1 MiB (utee maps STORAGE_NO_SPACE).
