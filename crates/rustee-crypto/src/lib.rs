#![no_std]
//! CryptoProvider. Kernel envelope verify calls `sha256` + `rsa_pkcs1_verify`.
//! SoftwareProvider smoke set is owned by rustee-crypto; defaults fail closed
//! until that impl lands. No RSA lives in rustee-os.

pub trait CryptoProvider {
    fn is_supported(&self, alg: u32) -> bool;

    /// SHA-256. Default is zeros (not a hash). Real impl in SoftwareProvider smoke set.
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let _ = data;
        [0; 32]
    }

    /// RSASSA-PKCS1-v1_5 SHA-256. Default false. No RSA in rustee-os.
    fn rsa_pkcs1_verify(&self, pubkey: &[u8], digest: &[u8; 32], signature: &[u8]) -> bool {
        let _ = (pubkey, digest, signature);
        false
    }
}

pub struct SoftwareProvider;
impl CryptoProvider for SoftwareProvider {
    fn is_supported(&self, _alg: u32) -> bool {
        false
    }
}

#[cfg(feature = "arith")]
pub mod arith {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn truthful_empty() {
        assert!(!SoftwareProvider.is_supported(0));
        assert!(!SoftwareProvider.rsa_pkcs1_verify(&[], &[0; 32], &[]));
    }
}
