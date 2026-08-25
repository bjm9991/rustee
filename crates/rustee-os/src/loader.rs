//! ELF stub loader. Early-TA or LOAD_TA bytes. Envelope verify via CryptoProvider.

use crate::abi::{Uuid, TEE_ERROR_SECURITY};
use crate::header::{
    find_ta_head, parse_rtsg, parse_ta_head, TaProperties, V0_DEV_PUBKEY, RTSG_MAGIC,
};
use rustee_crypto::CryptoProvider;

#[derive(Clone, Copy, Debug)]
pub struct EarlyTa {
    pub uuid: Uuid,
    pub props: TaProperties,
    pub image: &'static [u8],
}

pub struct EarlyTas {
    inner: alloc::vec::Vec<EarlyTa>,
}

impl EarlyTas {
    pub fn new() -> Self {
        Self {
            inner: alloc::vec::Vec::new(),
        }
    }
    pub fn insert(&mut self, ta: EarlyTa) {
        self.inner.push(ta);
    }
    pub fn get(&self, uuid: Uuid) -> Option<&EarlyTa> {
        self.inner.iter().find(|t| t.uuid == uuid)
    }
}

pub struct Loaded {
    pub props: TaProperties,
}

pub fn load_image<C: CryptoProvider>(crypto: &C, bytes: &[u8]) -> Result<Loaded, u32> {
    let elf = if bytes.len() >= 4
        && u32::from_le_bytes(bytes[0..4].try_into().unwrap()) == RTSG_MAGIC
    {
        let img = parse_rtsg(bytes)?;
        let mut hashed = alloc::vec::Vec::new();
        hashed.extend_from_slice(&img.uuid.0);
        hashed.extend_from_slice(&img.ta_version.to_le_bytes());
        hashed.extend_from_slice(img.elf);
        let digest = crypto.sha256(&hashed);
        if img.hash != digest.as_slice()
            || !crypto.rsa_pkcs1_verify(V0_DEV_PUBKEY, &digest, img.sig)
        {
            return Err(TEE_ERROR_SECURITY);
        }
        img.elf
    } else {
        bytes
    };
    let head = find_ta_head(elf)?;
    let props = parse_ta_head(head)?;
    Ok(Loaded { props })
}
