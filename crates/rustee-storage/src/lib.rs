#![no_std]
//! ree-fs: encrypted REE-backed objects. Not GP trusted storage. Not anti-rollback.

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use rustee_crypto::{hkdf_sha256, AesKey, CryptoError, SoftwareProvider};
use rustee_hal::{Entropy, Huk};

pub const MAX_OBJECT: usize = 1024 * 1024;
pub const STORAGE_CLASS_REE_FS: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    Corrupt,
    NotFound,
    TooBig,
    Crypto,
    Fs,
}

impl From<CryptoError> for StorageError {
    fn from(_: CryptoError) -> Self {
        StorageError::Crypto
    }
}

pub trait FsRpc {
    fn create(&mut self, path: &str, data: &[u8]) -> Result<(), StorageError>;
    fn read(&mut self, path: &str) -> Result<Vec<u8>, StorageError>;
    fn write(&mut self, path: &str, data: &[u8]) -> Result<(), StorageError>;
    fn delete(&mut self, path: &str) -> Result<(), StorageError>;
    fn mkdir(&mut self, path: &str) -> Result<(), StorageError>;
}

#[derive(Clone)]
pub struct ObjectMeta {
    pub object_id: Vec<u8>,
    pub flags: u32,
    pub data_size: u64,
}

#[derive(Debug)]
pub struct ObjectHandle {
    pub ta: [u8; 16],
    pub file_id: [u8; 16],
    pub object_id: Vec<u8>,
    pub flags: u32,
    pub data: Vec<u8>,
    pub obj_version: u64,
}

pub struct ReeFs<E, H, F> {
    entropy: E,
    huk: H,
    fs: F,
    provider: SoftwareProvider,
}

impl<E: Entropy, H: Huk, F: FsRpc> ReeFs<E, H, F> {
    pub fn new(entropy: E, huk: H, fs: F) -> Self {
        Self {
            entropy,
            huk,
            fs,
            provider: SoftwareProvider,
        }
    }

    fn tsk(&self, ta: &[u8; 16]) -> Result<[u8; 32], StorageError> {
        let mut ssk = [0u8; 32];
        hkdf_sha256(self.huk.material(), b"rustee.storage.ssk.v1", &mut ssk)?;
        let mut info = [0u8; 24];
        info[..16].copy_from_slice(b"rustee.storage.t");
        // info = "rustee.storage.ta.v1" || uuid
        let mut tsk = [0u8; 32];
        let mut inf = Vec::from(&b"rustee.storage.ta.v1"[..]);
        inf.extend_from_slice(ta);
        hkdf_sha256(&ssk, &inf, &mut tsk)?;
        let _ = info;
        Ok(tsk)
    }

    fn derive(tsk: &[u8; 32], info: &[u8]) -> Result<[u8; 32], StorageError> {
        let mut out = [0u8; 32];
        hkdf_sha256(tsk, info, &mut out)?;
        Ok(out)
    }

    fn ta_hex(ta: &[u8; 16]) -> String {
        hex32(ta)
    }

    fn dir_path(ta: &[u8; 16]) -> String {
        let mut s = Self::ta_hex(ta);
        s.push_str("/dir.v1");
        s
    }

    fn obj_path(ta: &[u8; 16], file_id: &[u8; 16]) -> String {
        let mut s = Self::ta_hex(ta);
        s.push_str("/obj/");
        s.push_str(&hex32(file_id));
        s
    }

    pub fn create(
        &mut self,
        ta: [u8; 16],
        object_id: &[u8],
        flags: u32,
        data: &[u8],
    ) -> Result<ObjectHandle, StorageError> {
        if data.len() > MAX_OBJECT {
            return Err(StorageError::TooBig);
        }
        let _ = self.fs.mkdir(&Self::ta_hex(&ta));
        let _ = self.fs.mkdir(&(Self::ta_hex(&ta) + "/obj"));
        let mut entries = self.load_dir(&ta).unwrap_or_default();
        if entries.iter().any(|e| e.object_id == object_id) {
            return Err(StorageError::Fs);
        }
        let mut file_id = [0u8; 16];
        self.entropy.fill(&mut file_id);
        let handle = ObjectHandle {
            ta,
            file_id,
            object_id: object_id.to_vec(),
            flags,
            data: data.to_vec(),
            obj_version: 1,
        };
        self.write_object(&handle)?;
        entries.push(ObjectMeta {
            object_id: object_id.to_vec(),
            flags,
            data_size: data.len() as u64,
        });
        // keep file_id map in a parallel vec stored in dir blob
        self.store_dir(&ta, &entries, &[(file_id, handle.obj_version)])?;
        Ok(handle)
    }

    pub fn list(&mut self, ta: [u8; 16]) -> Result<Vec<ObjectMeta>, StorageError> {
        self.load_dir(&ta)
    }

    pub fn open(&mut self, ta: [u8; 16], object_id: &[u8]) -> Result<ObjectHandle, StorageError> {
        let (entries, files) = self.load_dir_full(&ta)?;
        let idx = entries
            .iter()
            .position(|e| e.object_id == object_id)
            .ok_or(StorageError::NotFound)?;
        let file_id = files[idx].0;
        let blob = self
            .fs
            .read(&Self::obj_path(&ta, &file_id))
            .map_err(|_| StorageError::Corrupt)?;
        self.decrypt_object(ta, file_id, object_id, entries[idx].flags, files[idx].1, &blob)
    }

    pub fn read(h: &ObjectHandle, off: u64, buf: &mut [u8]) -> Result<usize, StorageError> {
        let start = off as usize;
        if start > h.data.len() {
            return Ok(0);
        }
        let n = core::cmp::min(buf.len(), h.data.len() - start);
        buf[..n].copy_from_slice(&h.data[start..start + n]);
        Ok(n)
    }

    pub fn write(
        &mut self,
        h: &mut ObjectHandle,
        off: u64,
        buf: &[u8],
    ) -> Result<usize, StorageError> {
        let start = off as usize;
        if start + buf.len() > MAX_OBJECT {
            return Err(StorageError::TooBig);
        }
        if start + buf.len() > h.data.len() {
            h.data.resize(start + buf.len(), 0);
        }
        h.data[start..start + buf.len()].copy_from_slice(buf);
        h.obj_version = h.obj_version.wrapping_add(1);
        self.write_object(h)?;
        self.upsert_dir(h)?;
        Ok(buf.len())
    }

    pub fn truncate(&mut self, h: &mut ObjectHandle, size: u64) -> Result<(), StorageError> {
        if size as usize > MAX_OBJECT {
            return Err(StorageError::TooBig);
        }
        h.data.resize(size as usize, 0);
        h.obj_version = h.obj_version.wrapping_add(1);
        self.write_object(h)?;
        self.upsert_dir(h)
    }

    pub fn delete(&mut self, ta: [u8; 16], object_id: &[u8]) -> Result<(), StorageError> {
        let (mut entries, mut files) = self.load_dir_full(&ta)?;
        let idx = entries
            .iter()
            .position(|e| e.object_id == object_id)
            .ok_or(StorageError::NotFound)?;
        let file_id = files[idx].0;
        let _ = self.fs.delete(&Self::obj_path(&ta, &file_id));
        entries.remove(idx);
        files.remove(idx);
        self.store_dir_full(&ta, &entries, &files)
    }

    pub fn rename(
        &mut self,
        ta: [u8; 16],
        old: &[u8],
        new: &[u8],
    ) -> Result<(), StorageError> {
        let mut h = self.open(ta, old)?;
        h.object_id = new.to_vec();
        h.obj_version = h.obj_version.wrapping_add(1);
        self.write_object(&h)?;
        self.delete(ta, old)?;
        let mut entries = self.load_dir(&ta).unwrap_or_default();
        entries.push(ObjectMeta {
            object_id: new.to_vec(),
            flags: h.flags,
            data_size: h.data.len() as u64,
        });
        self.store_dir(&ta, &entries, &[(h.file_id, h.obj_version)])
    }

    fn upsert_dir(&mut self, h: &ObjectHandle) -> Result<(), StorageError> {
        let (mut entries, mut files) = self.load_dir_full(&h.ta).unwrap_or_default();
        if let Some(i) = entries.iter().position(|e| e.object_id == h.object_id) {
            entries[i].data_size = h.data.len() as u64;
            entries[i].flags = h.flags;
            files[i] = (h.file_id, h.obj_version);
        } else {
            entries.push(ObjectMeta {
                object_id: h.object_id.clone(),
                flags: h.flags,
                data_size: h.data.len() as u64,
            });
            files.push((h.file_id, h.obj_version));
        }
        self.store_dir_full(&h.ta, &entries, &files)
    }

    fn write_object(&mut self, h: &ObjectHandle) -> Result<(), StorageError> {
        let tsk = self.tsk(&h.ta)?;
        let k_wrap = Self::derive(&tsk, b"rustee.storage.wrap.v1")?;
        let mut fek_bytes = [0u8; 32];
        self.entropy.fill(&mut fek_bytes);
        let fek = AesKey::from_bytes(&fek_bytes)?;
        let mut wrap_nonce = [0u8; 12];
        let mut body_nonce = [0u8; 12];
        self.entropy.fill(&mut wrap_nonce);
        self.entropy.fill(&mut body_nonce);
        let wrap_key = AesKey::from_bytes(&k_wrap)?;
        let mut wrapped = [0u8; 32];
        let mut wrap_tag = [0u8; 16];
        let mut aad = Vec::from(&b"RSTO"[..]);
        aad.push(1);
        aad.extend_from_slice(&h.ta);
        aad.extend_from_slice(&h.file_id);
        aad.extend_from_slice(&h.obj_version.to_le_bytes());
        self.provider.aes_gcm_encrypt(
            &wrap_key,
            &wrap_nonce,
            &aad,
            &fek_bytes,
            &mut wrapped,
            &mut wrap_tag,
        )?;
        let mut pt = Vec::new();
        pt.push(h.object_id.len() as u8);
        pt.extend_from_slice(&h.object_id);
        pt.extend_from_slice(&h.data);
        let mut ct = vec![0u8; pt.len()];
        let mut body_tag = [0u8; 16];
        let mut baad = aad.clone();
        baad.extend_from_slice(&(pt.len() as u64).to_le_bytes());
        self.provider.aes_gcm_encrypt(
            &fek,
            &body_nonce,
            &baad,
            &pt,
            &mut ct,
            &mut body_tag,
        )?;
        let mut blob = Vec::new();
        blob.extend_from_slice(b"RSTO");
        blob.push(1);
        blob.push(0);
        blob.extend_from_slice(&0u16.to_le_bytes());
        blob.extend_from_slice(&h.file_id);
        blob.extend_from_slice(&h.ta);
        blob.extend_from_slice(&h.obj_version.to_le_bytes());
        blob.extend_from_slice(&wrap_nonce);
        blob.extend_from_slice(&body_nonce);
        blob.extend_from_slice(&wrapped);
        blob.extend_from_slice(&wrap_tag);
        blob.extend_from_slice(&(pt.len() as u64).to_le_bytes());
        blob.extend_from_slice(&ct);
        blob.extend_from_slice(&body_tag);
        let path = Self::obj_path(&h.ta, &h.file_id);
        self.fs.write(&path, &blob).or_else(|_| self.fs.create(&path, &blob))
    }

    fn decrypt_object(
        &self,
        ta: [u8; 16],
        file_id: [u8; 16],
        object_id: &[u8],
        flags: u32,
        obj_version: u64,
        blob: &[u8],
    ) -> Result<ObjectHandle, StorageError> {
        if blob.len() < 128 || &blob[0..4] != b"RSTO" {
            return Err(StorageError::Corrupt);
        }
        let wrap_nonce: [u8; 12] = blob[48..60].try_into().unwrap();
        let body_nonce: [u8; 12] = blob[60..72].try_into().unwrap();
        let wrapped = &blob[72..104];
        let wrap_tag: [u8; 16] = blob[104..120].try_into().unwrap();
        let pt_len = u64::from_le_bytes(blob[120..128].try_into().unwrap()) as usize;
        if blob.len() < 128 + pt_len + 16 {
            return Err(StorageError::Corrupt);
        }
        let ct = &blob[128..128 + pt_len];
        let body_tag: [u8; 16] = blob[128 + pt_len..128 + pt_len + 16]
            .try_into()
            .unwrap();
        let tsk = self.tsk(&ta)?;
        let k_wrap = Self::derive(&tsk, b"rustee.storage.wrap.v1")?;
        let wrap_key = AesKey::from_bytes(&k_wrap)?;
        let mut aad = Vec::from(&b"RSTO"[..]);
        aad.push(1);
        aad.extend_from_slice(&ta);
        aad.extend_from_slice(&file_id);
        aad.extend_from_slice(&obj_version.to_le_bytes());
        let mut fek_bytes = [0u8; 32];
        self.provider
            .aes_gcm_decrypt(&wrap_key, &wrap_nonce, &aad, wrapped, &wrap_tag, &mut fek_bytes)
            .map_err(|_| StorageError::Corrupt)?;
        let fek = AesKey::from_bytes(&fek_bytes)?;
        let mut baad = aad;
        baad.extend_from_slice(&(pt_len as u64).to_le_bytes());
        let mut pt = vec![0u8; pt_len];
        self.provider
            .aes_gcm_decrypt(&fek, &body_nonce, &baad, ct, &body_tag, &mut pt)
            .map_err(|_| StorageError::Corrupt)?;
        if pt.is_empty() {
            return Err(StorageError::Corrupt);
        }
        let oid_len = pt[0] as usize;
        if pt.len() < 1 + oid_len {
            return Err(StorageError::Corrupt);
        }
        let oid = &pt[1..1 + oid_len];
        if oid != object_id {
            return Err(StorageError::Corrupt);
        }
        Ok(ObjectHandle {
            ta,
            file_id,
            object_id: oid.to_vec(),
            flags,
            data: pt[1 + oid_len..].to_vec(),
            obj_version,
        })
    }

    fn load_dir(&mut self, ta: &[u8; 16]) -> Result<Vec<ObjectMeta>, StorageError> {
        Ok(self.load_dir_full(ta)?.0)
    }

    fn load_dir_full(
        &mut self,
        ta: &[u8; 16],
    ) -> Result<(Vec<ObjectMeta>, Vec<([u8; 16], u64)>), StorageError> {
        let blob = self
            .fs
            .read(&Self::dir_path(ta))
            .map_err(|_| StorageError::NotFound)?;
        if blob.len() < 12 + 16 + 32 {
            return Err(StorageError::Corrupt);
        }
        let tsk = self.tsk(ta)?;
        let k_dir = Self::derive(&tsk, b"rustee.storage.dir.v1")?;
        let k_mac = Self::derive(&tsk, b"rustee.storage.mac.v1")?;
        let nonce: [u8; 12] = blob[..12].try_into().unwrap();
        let rest = &blob[12..];
        if rest.len() < 16 + 32 {
            return Err(StorageError::Corrupt);
        }
        let (ct_and_tag, mac) = rest.split_at(rest.len() - 32);
        let mut expect = [0u8; 32];
        self.provider
            .hmac_sha256(&k_mac, ct_and_tag, &mut expect)
            .map_err(|_| StorageError::Corrupt)?;
        if expect != mac {
            return Err(StorageError::Corrupt);
        }
        if ct_and_tag.len() < 16 {
            return Err(StorageError::Corrupt);
        }
        let (ct, tag) = ct_and_tag.split_at(ct_and_tag.len() - 16);
        let tag: [u8; 16] = tag.try_into().unwrap();
        let key = AesKey::from_bytes(&k_dir)?;
        let mut aad = Vec::from(&b"RSTE-dir-v1"[..]);
        aad.extend_from_slice(ta);
        let mut pt = vec![0u8; ct.len()];
        self.provider
            .aes_gcm_decrypt(&key, &nonce, &aad, ct, &tag, &mut pt)
            .map_err(|_| StorageError::Corrupt)?;
        parse_dir(&pt)
    }

    fn store_dir(
        &mut self,
        ta: &[u8; 16],
        entries: &[ObjectMeta],
        extra: &[([u8; 16], u64)],
    ) -> Result<(), StorageError> {
        let mut files = Vec::new();
        if let Ok((_, existing)) = self.load_dir_full(ta) {
            files = existing;
        }
        for (i, e) in extra.iter().enumerate() {
            if i < files.len() {
                files[i] = *e;
            } else {
                files.push(*e);
            }
        }
        self.store_dir_full(ta, entries, &files)
    }

    fn store_dir_full(
        &mut self,
        ta: &[u8; 16],
        entries: &[ObjectMeta],
        files: &[([u8; 16], u64)],
    ) -> Result<(), StorageError> {
        let mut pt = Vec::new();
        pt.extend_from_slice(b"RSTD");
        pt.push(1);
        pt.extend_from_slice(&[0, 0, 0]);
        pt.extend_from_slice(&1u64.to_le_bytes());
        pt.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (i, e) in entries.iter().enumerate() {
            let (fid, ver) = files.get(i).copied().unwrap_or(([0u8; 16], 1));
            pt.extend_from_slice(&fid);
            pt.push(e.object_id.len() as u8);
            pt.extend_from_slice(&e.object_id);
            pt.extend_from_slice(&e.flags.to_le_bytes());
            pt.extend_from_slice(&e.data_size.to_le_bytes());
            pt.extend_from_slice(&ver.to_le_bytes());
        }
        let tsk = self.tsk(ta)?;
        let k_dir = Self::derive(&tsk, b"rustee.storage.dir.v1")?;
        let k_mac = Self::derive(&tsk, b"rustee.storage.mac.v1")?;
        let mut nonce = [0u8; 12];
        self.entropy.fill(&mut nonce);
        let key = AesKey::from_bytes(&k_dir)?;
        let mut aad = Vec::from(&b"RSTE-dir-v1"[..]);
        aad.extend_from_slice(ta);
        let mut ct = vec![0u8; pt.len()];
        let mut tag = [0u8; 16];
        self.provider
            .aes_gcm_encrypt(&key, &nonce, &aad, &pt, &mut ct, &mut tag)?;
        let mut body = Vec::new();
        body.extend_from_slice(&ct);
        body.extend_from_slice(&tag);
        let mut mac = [0u8; 32];
        self.provider.hmac_sha256(&k_mac, &body, &mut mac)?;
        let mut blob = Vec::new();
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&body);
        blob.extend_from_slice(&mac);
        let path = Self::dir_path(ta);
        self.fs.write(&path, &blob).or_else(|_| self.fs.create(&path, &blob))
    }
}

fn parse_dir(pt: &[u8]) -> Result<(Vec<ObjectMeta>, Vec<([u8; 16], u64)>), StorageError> {
    if pt.len() < 20 || &pt[0..4] != b"RSTD" {
        return Err(StorageError::Corrupt);
    }
    let count = u32::from_le_bytes(pt[16..20].try_into().unwrap()) as usize;
    let mut off = 20;
    let mut entries = Vec::new();
    let mut files = Vec::new();
    for _ in 0..count {
        if off + 16 + 1 > pt.len() {
            return Err(StorageError::Corrupt);
        }
        let mut fid = [0u8; 16];
        fid.copy_from_slice(&pt[off..off + 16]);
        off += 16;
        let oid_len = pt[off] as usize;
        off += 1;
        if off + oid_len + 4 + 8 + 8 > pt.len() {
            return Err(StorageError::Corrupt);
        }
        let oid = pt[off..off + oid_len].to_vec();
        off += oid_len;
        let flags = u32::from_le_bytes(pt[off..off + 4].try_into().unwrap());
        off += 4;
        let data_size = u64::from_le_bytes(pt[off..off + 8].try_into().unwrap());
        off += 8;
        let ver = u64::from_le_bytes(pt[off..off + 8].try_into().unwrap());
        off += 8;
        entries.push(ObjectMeta {
            object_id: oid,
            flags,
            data_size,
        });
        files.push((fid, ver));
    }
    Ok((entries, files))
}

fn hex32(b: &[u8; 16]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(32);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use rustee_hal::{Entropy, EntropyOrigin, Huk};

    struct Mem(BTreeMap<String, Vec<u8>>);
    impl FsRpc for Mem {
        fn create(&mut self, path: &str, data: &[u8]) -> Result<(), StorageError> {
            self.0.insert(path.into(), data.to_vec());
            Ok(())
        }
        fn read(&mut self, path: &str) -> Result<Vec<u8>, StorageError> {
            self.0.get(path).cloned().ok_or(StorageError::NotFound)
        }
        fn write(&mut self, path: &str, data: &[u8]) -> Result<(), StorageError> {
            self.0.insert(path.into(), data.to_vec());
            Ok(())
        }
        fn delete(&mut self, path: &str) -> Result<(), StorageError> {
            self.0.remove(path);
            Ok(())
        }
        fn mkdir(&mut self, _path: &str) -> Result<(), StorageError> {
            Ok(())
        }
    }

    struct Ctr(u8);
    impl Entropy for Ctr {
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
    struct TestHuk;
    impl Huk for TestHuk {
        fn material(&self) -> &[u8] {
            b"0123456789abcdef0123456789abcdef"
        }
    }

    #[test]
    fn create_list_open() {
        let mut fs = ReeFs::new(Ctr(1), TestHuk, Mem(BTreeMap::new()));
        let ta = [9u8; 16];
        let h = fs.create(ta, b"oid-1", 0, b"hello").unwrap();
        let mut buf = [0u8; 8];
        let n = ReeFs::<Ctr, TestHuk, Mem>::read(&h, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        let list = fs.list(ta).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].object_id, b"oid-1");
        let h2 = fs.open(ta, b"oid-1").unwrap();
        assert_eq!(h2.data, b"hello");
        fs.delete(ta, b"oid-1").unwrap();
        assert!(fs.open(ta, b"oid-1").is_err());
    }

    #[test]
    fn too_big() {
        let mut fs = ReeFs::new(Ctr(1), TestHuk, Mem(BTreeMap::new()));
        let data = vec![0u8; MAX_OBJECT + 1];
        assert_eq!(
            fs.create([1u8; 16], b"x", 0, &data).unwrap_err(),
            StorageError::TooBig
        );
    }
}
