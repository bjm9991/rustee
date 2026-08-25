use crate::{
    AesBits, AesKey, AesKeyBytes, CryptoError, RsaBits, SoftwareProvider, ERng,
};
use aes::{
    cipher::{BlockEncrypt, BlockDecrypt, KeyInit},
    Aes128, Aes256,
};
use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use rustee_hal::Entropy;
use sha1::Sha1;
use sha2::{Digest, Sha256};

impl SoftwareProvider {
    pub fn hash_sha1(&self, data: &[u8], out: &mut [u8; 20]) -> Result<(), CryptoError> {
        out.copy_from_slice(&Sha1::digest(data));
        Ok(())
    }
    pub fn hash_sha256(&self, data: &[u8], out: &mut [u8; 32]) -> Result<(), CryptoError> {
        out.copy_from_slice(&Sha256::digest(data));
        Ok(())
    }
    pub fn hmac_sha1(&self, key: &[u8], data: &[u8], out: &mut [u8; 20]) -> Result<(), CryptoError> {
        let mut m = <Hmac<Sha1> as Mac>::new_from_slice(key).map_err(|_| CryptoError::KeyRejected)?;
        m.update(data);
        out.copy_from_slice(&m.finalize().into_bytes());
        Ok(())
    }
    pub fn hmac_sha256(&self, key: &[u8], data: &[u8], out: &mut [u8; 32]) -> Result<(), CryptoError> {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| CryptoError::KeyRejected)?;
        m.update(data);
        out.copy_from_slice(&m.finalize().into_bytes());
        Ok(())
    }

    fn aes_crypt(&self, key: &AesKey, data: &[u8], out: &mut [u8], encrypt: bool) -> Result<(), CryptoError> {
        if data.len() % 16 != 0 || out.len() != data.len() {
            return Err(CryptoError::InvalidLength);
        }
        match (&key.bytes, encrypt) {
            (AesKeyBytes::K128(k), true) => {
                let c = Aes128::new(k.into());
                for (i, chunk) in data.chunks(16).enumerate() {
                    let mut block = *aes::Block::from_slice(chunk);
                    c.encrypt_block(&mut block);
                    out[i * 16..][..16].copy_from_slice(&block);
                }
            }
            (AesKeyBytes::K128(k), false) => {
                let c = Aes128::new(k.into());
                for (i, chunk) in data.chunks(16).enumerate() {
                    let mut block = *aes::Block::from_slice(chunk);
                    c.decrypt_block(&mut block);
                    out[i * 16..][..16].copy_from_slice(&block);
                }
            }
            (AesKeyBytes::K256(k), true) => {
                let c = Aes256::new(k.into());
                for (i, chunk) in data.chunks(16).enumerate() {
                    let mut block = *aes::Block::from_slice(chunk);
                    c.encrypt_block(&mut block);
                    out[i * 16..][..16].copy_from_slice(&block);
                }
            }
            (AesKeyBytes::K256(k), false) => {
                let c = Aes256::new(k.into());
                for (i, chunk) in data.chunks(16).enumerate() {
                    let mut block = *aes::Block::from_slice(chunk);
                    c.decrypt_block(&mut block);
                    out[i * 16..][..16].copy_from_slice(&block);
                }
            }
        }
        Ok(())
    }

    pub fn aes_ecb_encrypt(&self, key: &AesKey, pt: &[u8], ct: &mut [u8]) -> Result<(), CryptoError> {
        self.aes_crypt(key, pt, ct, true)
    }
    pub fn aes_ecb_decrypt(&self, key: &AesKey, ct: &[u8], pt: &mut [u8]) -> Result<(), CryptoError> {
        self.aes_crypt(key, ct, pt, false)
    }

    pub fn aes_cbc_encrypt(
        &self,
        key: &AesKey,
        iv: &[u8; 16],
        pt: &[u8],
        ct: &mut [u8],
    ) -> Result<(), CryptoError> {
        if pt.len() % 16 != 0 || ct.len() != pt.len() {
            return Err(CryptoError::InvalidLength);
        }
        let mut prev = *iv;
        let mut block = [0u8; 16];
        let mut outb = [0u8; 16];
        for (i, chunk) in pt.chunks(16).enumerate() {
            for j in 0..16 {
                block[j] = chunk[j] ^ prev[j];
            }
            self.aes_crypt(key, &block, &mut outb, true)?;
            ct[i * 16..][..16].copy_from_slice(&outb);
            prev = outb;
        }
        Ok(())
    }

    pub fn aes_cbc_decrypt(
        &self,
        key: &AesKey,
        iv: &[u8; 16],
        ct: &[u8],
        pt: &mut [u8],
    ) -> Result<(), CryptoError> {
        if ct.len() % 16 != 0 || pt.len() != ct.len() {
            return Err(CryptoError::InvalidLength);
        }
        let mut prev = *iv;
        let mut dec = [0u8; 16];
        for (i, chunk) in ct.chunks(16).enumerate() {
            self.aes_crypt(key, chunk, &mut dec, false)?;
            for j in 0..16 {
                pt[i * 16 + j] = dec[j] ^ prev[j];
            }
            prev.copy_from_slice(chunk);
        }
        Ok(())
    }

    pub fn aes_ctr(&self, key: &AesKey, iv: &[u8; 16], inout: &mut [u8]) -> Result<(), CryptoError> {
        let mut ctr = *iv;
        let mut ks = [0u8; 16];
        let mut off = 0;
        while off < inout.len() {
            self.aes_crypt(key, &ctr, &mut ks, true)?;
            let n = core::cmp::min(16, inout.len() - off);
            for i in 0..n {
                inout[off + i] ^= ks[i];
            }
            // increment 128-bit counter big-endian
            for i in (0..16).rev() {
                ctr[i] = ctr[i].wrapping_add(1);
                if ctr[i] != 0 {
                    break;
                }
            }
            off += n;
        }
        Ok(())
    }

    pub fn aes_gcm_encrypt(
        &self,
        key: &AesKey,
        nonce: &[u8; 12],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        if ct.len() != pt.len() {
            return Err(CryptoError::InvalidLength);
        }
        use aes_gcm::{
            aead::{Aead, KeyInit as AeadKeyInit, Payload},
            Aes128Gcm, Aes256Gcm, Nonce,
        };
        let n = Nonce::from_slice(nonce);
        let out = match key.bits {
            AesBits::Aes128 => {
                let k = AesKey::from_bytes(key.as_slice())?;
                let _ = k;
                Aes128Gcm::new(key.as_slice().into())
                    .encrypt(n, Payload { msg: pt, aad })
                    .map_err(|_| CryptoError::AuthFailure)?
            }
            AesBits::Aes256 => Aes256Gcm::new(key.as_slice().into())
                .encrypt(n, Payload { msg: pt, aad })
                .map_err(|_| CryptoError::AuthFailure)?,
        };
        if out.len() != pt.len() + 16 {
            return Err(CryptoError::InvalidLength);
        }
        ct.copy_from_slice(&out[..pt.len()]);
        tag.copy_from_slice(&out[pt.len()..]);
        Ok(())
    }

    pub fn aes_gcm_decrypt(
        &self,
        key: &AesKey,
        nonce: &[u8; 12],
        aad: &[u8],
        ct: &[u8],
        tag: &[u8; 16],
        pt: &mut [u8],
    ) -> Result<(), CryptoError> {
        if pt.len() != ct.len() {
            return Err(CryptoError::InvalidLength);
        }
        use aes_gcm::{
            aead::{Aead, KeyInit as AeadKeyInit, Payload},
            Aes128Gcm, Aes256Gcm, Nonce,
        };
        let mut packed = Vec::with_capacity(ct.len() + 16);
        packed.extend_from_slice(ct);
        packed.extend_from_slice(tag);
        let n = Nonce::from_slice(nonce);
        let out = match key.bits {
            AesBits::Aes128 => Aes128Gcm::new(key.as_slice().into())
                .decrypt(n, Payload { msg: &packed, aad })
                .map_err(|_| CryptoError::AuthFailure)?,
            AesBits::Aes256 => Aes256Gcm::new(key.as_slice().into())
                .decrypt(n, Payload { msg: &packed, aad })
                .map_err(|_| CryptoError::AuthFailure)?,
        };
        pt.copy_from_slice(&out);
        Ok(())
    }

    pub fn generate_aes<E: Entropy>(
        &self,
        bits: AesBits,
        rng: &mut E,
    ) -> Result<AesKey, CryptoError> {
        crate::SoftwareProvider::check_entropy(rng.origin())?;
        match bits {
            AesBits::Aes128 => {
                let mut b = [0u8; 16];
                rng.fill(&mut b);
                AesKey::from_bytes(&b)
            }
            AesBits::Aes256 => {
                let mut b = [0u8; 32];
                rng.fill(&mut b);
                AesKey::from_bytes(&b)
            }
        }
    }
}

pub struct RsaPublic {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

/// PKCS#1 DER, SPKI DER, raw modulus (256/384, e=65537), or n||e (e last 3 bytes).
pub fn parse_rsa_public(bytes: &[u8]) -> Result<RsaPublic, CryptoError> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;
    if bytes.first() == Some(&0x30) {
        if let Ok(k) = rsa::RsaPublicKey::from_pkcs1_der(bytes) {
            return Ok(RsaPublic {
                n: k.n().to_bytes_be(),
                e: k.e().to_bytes_be(),
            });
        }
        if let Ok(k) = rsa::RsaPublicKey::from_public_key_der(bytes) {
            return Ok(RsaPublic {
                n: k.n().to_bytes_be(),
                e: k.e().to_bytes_be(),
            });
        }
    }
    match bytes.len() {
        256 | 384 => Ok(RsaPublic {
            n: bytes.to_vec(),
            e: alloc::vec![0x01, 0x00, 0x01],
        }),
        259 | 387 => {
            let nlen = bytes.len() - 3;
            Ok(RsaPublic {
                n: bytes[..nlen].to_vec(),
                e: bytes[nlen..].to_vec(),
            })
        }
        _ => Err(CryptoError::KeyRejected),
    }
}

pub struct RsaPrivate {
    inner: rsa::RsaPrivateKey,
}

pub struct P256Public(pub [u8; 65]);
pub struct P256Secret([u8; 32]);

impl Drop for P256Secret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl SoftwareProvider {
    pub fn generate_rsa<E: Entropy>(
        &self,
        bits: RsaBits,
        rng: &mut E,
    ) -> Result<(RsaPublic, RsaPrivate), CryptoError> {
        crate::SoftwareProvider::check_entropy(rng.origin())?;
        let mut er = ERng(rng);
        let inner = rsa::RsaPrivateKey::new(&mut er, bits.bits()).map_err(|_| CryptoError::KeyRejected)?;
        let pk = inner.to_public_key();
        use rsa::traits::PublicKeyParts;
        Ok((
            RsaPublic {
                n: pk.n().to_bytes_be(),
                e: pk.e().to_bytes_be(),
            },
            RsaPrivate { inner },
        ))
    }

    fn rsa_pub(&self, pk: &RsaPublic) -> Result<rsa::RsaPublicKey, CryptoError> {
        use rsa::BigUint;
        rsa::RsaPublicKey::new(BigUint::from_bytes_be(&pk.n), BigUint::from_bytes_be(&pk.e))
            .map_err(|_| CryptoError::KeyRejected)
    }

    pub fn rsa_pss_sign<E: Entropy>(
        &self,
        sk: &RsaPrivate,
        digest: &[u8; 32],
        sig: &mut [u8],
        rng: &mut E,
    ) -> Result<usize, CryptoError> {
        crate::SoftwareProvider::check_entropy(rng.origin())?;
        use rsa::pss::Pss;
        use sha2::Sha256;
        let mut er = ERng(rng);
        let out = sk
            .inner
            .sign_with_rng(&mut er, Pss::new::<Sha256>(), digest)
            .map_err(|_| CryptoError::KeyRejected)?;
        if sig.len() < out.len() {
            return Err(CryptoError::InvalidLength);
        }
        sig[..out.len()].copy_from_slice(&out);
        Ok(out.len())
    }

    pub fn rsa_pkcs1_sign(
        &self,
        sk: &RsaPrivate,
        digest: &[u8; 32],
        sig: &mut [u8],
    ) -> Result<usize, CryptoError> {
        use rsa::Pkcs1v15Sign;
        use sha2::Sha256;
        let out = sk
            .inner
            .sign(Pkcs1v15Sign::new::<Sha256>(), digest)
            .map_err(|_| CryptoError::KeyRejected)?;
        if sig.len() < out.len() {
            return Err(CryptoError::InvalidLength);
        }
        sig[..out.len()].copy_from_slice(&out);
        Ok(out.len())
    }

    pub fn rsa_pkcs1_verify_key(
        &self,
        pk: &RsaPublic,
        digest: &[u8; 32],
        sig: &[u8],
    ) -> Result<(), CryptoError> {
        use rsa::Pkcs1v15Sign;
        use sha2::Sha256;
        let key = self.rsa_pub(pk)?;
        key.verify(Pkcs1v15Sign::new::<Sha256>(), digest, sig)
            .map_err(|_| CryptoError::AuthFailure)
    }

    pub fn rsa_pss_verify(
        &self,
        pk: &RsaPublic,
        digest: &[u8; 32],
        sig: &[u8],
    ) -> Result<(), CryptoError> {
        use rsa::pss::Pss;
        use sha2::Sha256;
        let key = self.rsa_pub(pk)?;
        key.verify(Pss::new::<Sha256>(), digest, sig)
            .map_err(|_| CryptoError::AuthFailure)
    }

    pub fn rsa_oaep_encrypt<E: Entropy>(
        &self,
        pk: &RsaPublic,
        pt: &[u8],
        ct: &mut [u8],
        rng: &mut E,
    ) -> Result<usize, CryptoError> {
        crate::SoftwareProvider::check_entropy(rng.origin())?;
        use rsa::Oaep;
        use sha2::Sha256;
        let key = self.rsa_pub(pk)?;
        let mut er = ERng(rng);
        let out = key
            .encrypt(&mut er, Oaep::new::<Sha256>(), pt)
            .map_err(|_| CryptoError::KeyRejected)?;
        if ct.len() < out.len() {
            return Err(CryptoError::InvalidLength);
        }
        ct[..out.len()].copy_from_slice(&out);
        Ok(out.len())
    }

    pub fn rsa_oaep_decrypt(
        &self,
        sk: &RsaPrivate,
        ct: &[u8],
        pt: &mut [u8],
    ) -> Result<usize, CryptoError> {
        use rsa::Oaep;
        use sha2::Sha256;
        let out = sk
            .inner
            .decrypt(Oaep::new::<Sha256>(), ct)
            .map_err(|_| CryptoError::AuthFailure)?;
        if pt.len() < out.len() {
            return Err(CryptoError::InvalidLength);
        }
        pt[..out.len()].copy_from_slice(&out);
        Ok(out.len())
    }

    pub fn generate_p256<E: Entropy>(
        &self,
        rng: &mut E,
    ) -> Result<(P256Public, P256Secret), CryptoError> {
        crate::SoftwareProvider::check_entropy(rng.origin())?;
        let mut er = ERng(rng);
        let sk = p256::ecdsa::SigningKey::random(&mut er);
        let point = p256::EncodedPoint::from(sk.verifying_key());
        let sl = point.as_bytes();
        if sl.len() != 65 {
            return Err(CryptoError::KeyRejected);
        }
        let mut uncompressed = [0u8; 65];
        uncompressed.copy_from_slice(sl);
        let mut sec = [0u8; 32];
        sec.copy_from_slice(sk.to_bytes().as_slice());
        Ok((P256Public(uncompressed), P256Secret(sec)))
    }

    pub fn ecdsa_p256_sign(
        &self,
        sk: &P256Secret,
        digest: &[u8; 32],
        sig: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
        let key = SigningKey::from_bytes((&sk.0).into()).map_err(|_| CryptoError::KeyRejected)?;
        let s: p256::ecdsa::Signature = key
            .sign_prehash(digest)
            .map_err(|_| CryptoError::KeyRejected)?;
        sig.copy_from_slice(&s.to_bytes());
        Ok(())
    }

    pub fn ecdsa_p256_verify(
        &self,
        pk: &P256Public,
        digest: &[u8; 32],
        sig: &[u8; 64],
    ) -> Result<(), CryptoError> {
        use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
        let vk = VerifyingKey::from_sec1_bytes(&pk.0).map_err(|_| CryptoError::KeyRejected)?;
        let signature = Signature::from_slice(sig).map_err(|_| CryptoError::AuthFailure)?;
        vk.verify_prehash(digest, &signature)
            .map_err(|_| CryptoError::AuthFailure)
    }
}
