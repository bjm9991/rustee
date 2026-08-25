#![no_std]

pub trait CryptoProvider {
    fn is_supported(&self, alg: u32) -> bool;
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
    }
}
