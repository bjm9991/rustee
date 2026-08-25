#![no_std]
//! CryptoProvider + Arith math. No TEE_* names. GPD_SPE_010 identifiers are numeric.
//! Kernel envelope verify calls `sha256` + `rsa_pkcs1_verify` (fail-closed defaults).

extern crate alloc;

use rustee_hal::{Entropy, EntropyOrigin};

pub const ENTROPY_REE_NOTICE: &str =
    "RUSTEE entropy is REE-sourced (virt/host); not a product TEE RNG";
pub const HUK_REE_NOTICE: &str = "RUSTEE HUK is a development test key; not a product HUK";

/// Table 6-11 identifiers used by is_supported. Names are not TEE_*.
pub mod alg {
    pub const AES_ECB_NOPAD: u32 = 0x1000_0010;
    pub const AES_CBC_NOPAD: u32 = 0x1000_0110;
    pub const AES_CTR: u32 = 0x1000_0210;
    pub const AES_GCM: u32 = 0x4000_0810;
    pub const SHA1: u32 = 0x5000_0002;
    pub const SHA256: u32 = 0x5000_0004;
    pub const HMAC_SHA1: u32 = 0x3000_0002;
    pub const HMAC_SHA256: u32 = 0x3000_0004;
    pub const RSASSA_PKCS1_V1_5_SHA256: u32 = 0x7000_4830;
    pub const RSASSA_PKCS1_PSS_MGF1_SHA256: u32 = 0x7041_4930;
    pub const RSAES_PKCS1_OAEP_MGF1_SHA256: u32 = 0x6041_0230;
    pub const ECDSA_SHA256: u32 = 0x7000_3042;
    pub const HKDF: u32 = 0x8000_0047;
    pub const ELEMENT_NONE: u32 = 0;
    pub const ECC_NIST_P256: u32 = 3;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    Unsupported,
    InvalidLength,
    InvalidNonce,
    AuthFailure,
    KeyRejected,
    Entropy,
    ReeEntropyNotAllowed,
    ReeHukNotAllowed,
}

pub trait CryptoProvider {
    /// One-arg form used by kernel and utee (`TEE_IsAlgorithmSupported` forwards here).
    fn is_supported(&self, alg: u32) -> bool;

    /// Curve / object element. Default ignores `element`.
    fn is_supported_element(&self, alg: u32, element: u32) -> bool {
        let _ = element;
        self.is_supported(alg)
    }

    /// SHA-256. Default is zeros (not a hash). SoftwareProvider overrides.
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let _ = data;
        [0; 32]
    }

    /// RSASSA-PKCS1-v1_5 SHA-256. `pubkey` is PKCS#1 DER, SPKI, raw n (256/384, e=65537),
    /// or n||e. Default false. No RSA in rustee-os.
    fn rsa_pkcs1_verify(&self, pubkey: &[u8], digest: &[u8; 32], signature: &[u8]) -> bool {
        let _ = (pubkey, digest, signature);
        false
    }
}

#[derive(Clone, Copy)]
pub enum AesBits {
    Aes128,
    Aes256,
}

pub struct AesKey {
    bits: AesBits,
    bytes: AesKeyBytes,
}

enum AesKeyBytes {
    K128([u8; 16]),
    K256([u8; 32]),
}

impl Drop for AesKey {
    fn drop(&mut self) {
        match &mut self.bytes {
            AesKeyBytes::K128(b) => b.fill(0),
            AesKeyBytes::K256(b) => b.fill(0),
        }
    }
}

impl AesKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        match bytes.len() {
            16 => {
                let mut k = [0u8; 16];
                k.copy_from_slice(bytes);
                Ok(Self {
                    bits: AesBits::Aes128,
                    bytes: AesKeyBytes::K128(k),
                })
            }
            32 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(bytes);
                Ok(Self {
                    bits: AesBits::Aes256,
                    bytes: AesKeyBytes::K256(k),
                })
            }
            _ => Err(CryptoError::InvalidLength),
        }
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        match &self.bytes {
            AesKeyBytes::K128(b) => b,
            AesKeyBytes::K256(b) => b,
        }
    }
}

#[derive(Clone, Copy)]
pub enum RsaBits {
    Rsa2048,
    Rsa3072,
}

impl RsaBits {
    fn bits(self) -> usize {
        match self {
            RsaBits::Rsa2048 => 2048,
            RsaBits::Rsa3072 => 3072,
        }
    }
}

pub struct SoftwareProvider;

impl SoftwareProvider {
    pub fn check_entropy(origin: EntropyOrigin) -> Result<(), CryptoError> {
        match origin {
            EntropyOrigin::Isolated => Ok(()),
            EntropyOrigin::ReeHost => {
                #[cfg(feature = "allow-ree-entropy")]
                {
                    let _ = ENTROPY_REE_NOTICE;
                    Ok(())
                }
                #[cfg(not(feature = "allow-ree-entropy"))]
                {
                    Err(CryptoError::ReeEntropyNotAllowed)
                }
            }
        }
    }
}

impl CryptoProvider for SoftwareProvider {
    fn is_supported(&self, alg: u32) -> bool {
        use alg::*;
        matches!(
            alg,
            AES_ECB_NOPAD
                | AES_CBC_NOPAD
                | AES_CTR
                | AES_GCM
                | SHA1
                | SHA256
                | HMAC_SHA1
                | HMAC_SHA256
                | RSASSA_PKCS1_V1_5_SHA256
                | RSASSA_PKCS1_PSS_MGF1_SHA256
                | RSAES_PKCS1_OAEP_MGF1_SHA256
                | ECDSA_SHA256
        )
    }

    fn is_supported_element(&self, alg: u32, element: u32) -> bool {
        use alg::*;
        match alg {
            ECDSA_SHA256 => element == ECC_NIST_P256,
            _ => element == ELEMENT_NONE && self.is_supported(alg),
        }
    }

    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut d = [0u8; 32];
        let _ = self.hash_sha256(data, &mut d);
        d
    }

    fn rsa_pkcs1_verify(&self, pubkey: &[u8], digest: &[u8; 32], signature: &[u8]) -> bool {
        let Ok(pk) = parse_rsa_public(pubkey) else {
            return false;
        };
        self.rsa_pkcs1_verify_key(&pk, digest, signature).is_ok()
    }
}

struct ERng<'a, E: Entropy>(&'a mut E);

impl<E: Entropy> rand_core::RngCore for ERng<'_, E> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.0.fill(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.fill(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.fill(dest);
        Ok(())
    }
}
impl<E: Entropy> rand_core::CryptoRng for ERng<'_, E> {}

pub fn fill_random<E: Entropy>(rng: &mut E, buf: &mut [u8]) -> Result<(), CryptoError> {
    SoftwareProvider::check_entropy(rng.origin())?;
    rng.fill(buf);
    Ok(())
}

mod provider;
pub use provider::*;

#[cfg(feature = "arith")]
pub mod arith;

/// Crate-internal HKDF-SHA256 for ree-fs SSK/TSK. Not GP TEE_ALG_HKDF.
pub fn hkdf_sha256(ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), CryptoError> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let h = Hkdf::<Sha256>::new(None, ikm);
    h.expand(info, okm).map_err(|_| CryptoError::InvalidLength)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustee_hal::Entropy;

    struct CtrEntropy(u8);
    impl Entropy for CtrEntropy {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
        fn origin(&self) -> EntropyOrigin {
            EntropyOrigin::Isolated
        }
    }

    #[test]
    fn smoke_supported() {
        let p = SoftwareProvider;
        assert!(p.is_supported(alg::AES_GCM));
        assert!(p.is_supported(alg::SHA1));
        assert!(p.is_supported(alg::SHA256));
        assert!(p.is_supported(alg::HMAC_SHA1));
        assert!(p.is_supported(alg::HMAC_SHA256));
        assert!(p.is_supported(alg::RSASSA_PKCS1_V1_5_SHA256));
        assert!(p.is_supported(alg::RSASSA_PKCS1_PSS_MGF1_SHA256));
        assert!(p.is_supported(alg::RSAES_PKCS1_OAEP_MGF1_SHA256));
        assert!(p.is_supported(alg::ECDSA_SHA256));
        assert!(p.is_supported_element(alg::AES_GCM, alg::ELEMENT_NONE));
        assert!(p.is_supported_element(alg::ECDSA_SHA256, alg::ECC_NIST_P256));
        assert!(!p.is_supported_element(alg::ECDSA_SHA256, 0));
        assert!(!p.is_supported(alg::HKDF));
        assert!(!p.is_supported(0x1000_0310)); // CTS backlog
        assert!(!p.is_supported(0x6000_0130)); // PKCS1-v1.5 encrypt backlog
        assert!(!p.is_supported(0));
        assert!(!p.rsa_pkcs1_verify(&[], &[0; 32], &[]));
        assert!(!p.rsa_pkcs1_verify(b"RUSTEE-V0-DEV-PUBKEY-PLACEHOLDER!", &[0; 32], &[]));
    }

    #[test]
    fn sha_hmac_roundtrip() {
        let p = SoftwareProvider;
        let mut d = [0u8; 32];
        p.hash_sha256(b"abc", &mut d).unwrap();
        assert_eq!(
            d,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
        assert_eq!(p.sha256(b"abc"), d);
        let mut h = [0u8; 20];
        p.hash_sha1(b"abc", &mut h).unwrap();
        assert_eq!(
            h,
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
    }

    #[test]
    fn aes_gcm_roundtrip() {
        let p = SoftwareProvider;
        let key = AesKey::from_bytes(&[7u8; 32]).unwrap();
        let nonce = [1u8; 12];
        let pt = b"hello rustee gcm";
        let mut ct = [0u8; 16];
        let mut tag = [0u8; 16];
        p.aes_gcm_encrypt(&key, &nonce, b"aad", pt, &mut ct, &mut tag)
            .unwrap();
        let mut out = [0u8; 16];
        p.aes_gcm_decrypt(&key, &nonce, b"aad", &ct, &tag, &mut out)
            .unwrap();
        assert_eq!(&out, pt);
        tag[0] ^= 1;
        assert_eq!(
            p.aes_gcm_decrypt(&key, &nonce, b"aad", &ct, &tag, &mut out),
            Err(CryptoError::AuthFailure)
        );
    }

    struct Xs(u64);
    impl Entropy for Xs {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                *b = self.0 as u8;
            }
        }
        fn origin(&self) -> EntropyOrigin {
            EntropyOrigin::Isolated
        }
    }

    #[test]
    fn rsa_pkcs1_and_oaep() {
        let p = SoftwareProvider;
        let mut rng = Xs(0x9e3779b97f4a7c15);
        let (pk, sk) = p.generate_rsa(RsaBits::Rsa2048, &mut rng).unwrap();
        let mut digest = [0u8; 32];
        p.hash_sha256(b"digest", &mut digest).unwrap();
        let mut sig = alloc::vec![0u8; 256];
        let n = p.rsa_pkcs1_sign(&sk, &digest, &mut sig).unwrap();
        p.rsa_pkcs1_verify_key(&pk, &digest, &sig[..n]).unwrap();
        let mut encoded = pk.n.clone();
        encoded.extend_from_slice(&pk.e);
        assert!(CryptoProvider::rsa_pkcs1_verify(
            &p,
            &encoded,
            &digest,
            &sig[..n]
        ));
        {
            use rsa::BigUint;
            use rsa::pkcs8::EncodePublicKey;
            let rsa_pk = rsa::RsaPublicKey::new(
                BigUint::from_bytes_be(&pk.n),
                BigUint::from_bytes_be(&pk.e),
            )
            .unwrap();
            let spki = rsa_pk.to_public_key_der().unwrap();
            assert!(spki.as_bytes().first() == Some(&0x30));
            assert!(CryptoProvider::rsa_pkcs1_verify(
                &p,
                spki.as_bytes(),
                &digest,
                &sig[..n]
            ));
        }
        let pt = b"oaep-payload";
        let mut ct = alloc::vec![0u8; 256];
        let cl = p.rsa_oaep_encrypt(&pk, pt, &mut ct, &mut rng).unwrap();
        let mut out = [0u8; 64];
        let ol = p.rsa_oaep_decrypt(&sk, &ct[..cl], &mut out).unwrap();
        assert_eq!(&out[..ol], pt);
    }

    #[test]
    fn v0_dev_spki_pkcs1_verify() {
        // Public SPKI from rustee-os #6. Private key is not in this crate.
        let p = SoftwareProvider;
        let spki = include_bytes!("../testdata/v0-dev.spki.der");
        let sig = include_bytes!("../testdata/v0-dev-digest.sig");
        assert_eq!(spki.len(), 294);
        assert_eq!(spki[0], 0x30);
        assert!(parse_rsa_public(spki).is_ok());
        let digest = p.sha256(b"digest");
        assert!(CryptoProvider::rsa_pkcs1_verify(&p, spki, &digest, sig));
        let mut bad = *sig;
        bad[0] ^= 1;
        assert!(!CryptoProvider::rsa_pkcs1_verify(&p, spki, &digest, &bad));
    }

    #[test]
    fn ecdsa_roundtrip() {
        let p = SoftwareProvider;
        let mut rng = CtrEntropy(1);
        let (pk, sk) = p.generate_p256(&mut rng).unwrap();
        let mut digest = [0u8; 32];
        p.hash_sha256(b"msg", &mut digest).unwrap();
        let mut sig = [0u8; 64];
        p.ecdsa_p256_sign(&sk, &digest, &mut sig).unwrap();
        p.ecdsa_p256_verify(&pk, &digest, &sig).unwrap();
        sig[0] ^= 1;
        assert_eq!(
            p.ecdsa_p256_verify(&pk, &digest, &sig),
            Err(CryptoError::AuthFailure)
        );
    }
}
