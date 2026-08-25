//! rustee-supplicant RPC handlers. Not TCB.
//! GET_TIME, FS, LOAD_TA. Sockets later.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rustee_proto::{
    RPC_CMD_FS, RPC_CMD_GET_TIME, RPC_CMD_LOAD_TA, RPC_FS_CLOSE, RPC_FS_CLOSEDIR, RPC_FS_CREATE,
    RPC_FS_OPEN, RPC_FS_OPENDIR, RPC_FS_READ, RPC_FS_READDIR, RPC_FS_REMOVE, RPC_FS_RENAME,
    RPC_FS_TRUNCATE, RPC_FS_WRITE,
};

#[derive(Debug)]
pub enum SuppError {
    BadCmd,
    Io,
    NotFound,
}

pub struct Supplicant {
    root: PathBuf,
    files: HashMap<u32, File>,
    dirs: HashMap<u32, fs::ReadDir>,
    next_fd: u32,
}

impl Supplicant {
    pub fn new(root: PathBuf) -> std::io::Result<Self> {
        fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            files: HashMap::new(),
            dirs: HashMap::new(),
            next_fd: 1,
        })
    }

    pub fn get_time(&self) -> (u32, u32) {
        let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        (d.as_secs() as u32, d.subsec_nanos())
    }

    pub fn load_ta(&self, uuid_hex: &str) -> Result<Vec<u8>, SuppError> {
        let p = self.root.join("ta").join(format!("{uuid_hex}.ta"));
        fs::read(p).map_err(|_| SuppError::NotFound)
    }

    fn fd(&mut self) -> u32 {
        let n = self.next_fd;
        self.next_fd += 1;
        n
    }

    fn safe(root: &Path, name: &str) -> Result<PathBuf, SuppError> {
        if name.contains("..") || name.starts_with('/') {
            return Err(SuppError::BadCmd);
        }
        Ok(root.join(name))
    }

    pub fn fs(&mut self, op: u32, name: &str, fd: u32, off: u32, data: &[u8]) -> Result<(u32, Vec<u8>), SuppError> {
        match op {
            RPC_FS_OPEN | RPC_FS_CREATE => {
                let p = Self::safe(&self.root, name)?;
                let f = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(op == RPC_FS_CREATE)
                    .open(p)
                    .map_err(|_| SuppError::Io)?;
                let id = self.fd();
                self.files.insert(id, f);
                Ok((id, Vec::new()))
            }
            RPC_FS_CLOSE => {
                self.files.remove(&fd);
                Ok((0, Vec::new()))
            }
            RPC_FS_READ => {
                let f = self.files.get_mut(&fd).ok_or(SuppError::NotFound)?;
                f.seek(SeekFrom::Start(off as u64)).map_err(|_| SuppError::Io)?;
                let mut buf = vec![0u8; data.len().max(1)];
                let n = f.read(&mut buf).map_err(|_| SuppError::Io)?;
                buf.truncate(n);
                Ok((n as u32, buf))
            }
            RPC_FS_WRITE => {
                let f = self.files.get_mut(&fd).ok_or(SuppError::NotFound)?;
                f.seek(SeekFrom::Start(off as u64)).map_err(|_| SuppError::Io)?;
                f.write_all(data).map_err(|_| SuppError::Io)?;
                Ok((data.len() as u32, Vec::new()))
            }
            RPC_FS_TRUNCATE => {
                let f = self.files.get_mut(&fd).ok_or(SuppError::NotFound)?;
                f.set_len(off as u64).map_err(|_| SuppError::Io)?;
                Ok((0, Vec::new()))
            }
            RPC_FS_REMOVE => {
                let p = Self::safe(&self.root, name)?;
                let _ = fs::remove_file(p);
                Ok((0, Vec::new()))
            }
            RPC_FS_RENAME => Err(SuppError::BadCmd),
            RPC_FS_OPENDIR => {
                let p = Self::safe(&self.root, name)?;
                let d = fs::read_dir(p).map_err(|_| SuppError::Io)?;
                let id = self.fd();
                self.dirs.insert(id, d);
                Ok((id, Vec::new()))
            }
            RPC_FS_CLOSEDIR => {
                self.dirs.remove(&fd);
                Ok((0, Vec::new()))
            }
            RPC_FS_READDIR => {
                let d = self.dirs.get_mut(&fd).ok_or(SuppError::NotFound)?;
                match d.next() {
                    Some(Ok(e)) => {
                        let s = e.file_name().to_string_lossy().into_owned();
                        Ok((0, s.into_bytes()))
                    }
                    _ => Ok((0, Vec::new())),
                }
            }
            _ => Err(SuppError::BadCmd),
        }
    }

    pub fn rpc_cmd(cmd: u32) -> Result<(), SuppError> {
        match cmd {
            RPC_CMD_LOAD_TA | RPC_CMD_GET_TIME | RPC_CMD_FS => Ok(()),
            _ => Err(SuppError::BadCmd),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn time_and_fs_roundtrip() {
        let dir = env::temp_dir().join("rustee-supp-test");
        let mut s = Supplicant::new(dir.clone()).unwrap();
        let (sec, _ns) = s.get_time();
        assert!(sec > 0);
        assert!(Supplicant::rpc_cmd(RPC_CMD_GET_TIME).is_ok());
        assert!(Supplicant::rpc_cmd(RPC_CMD_LOAD_TA).is_ok());
        let (fd, _) = s.fs(RPC_FS_CREATE, "obj.bin", 0, 0, &[]).unwrap();
        s.fs(RPC_FS_WRITE, "", fd, 0, b"abc").unwrap();
        let (_n, data) = s.fs(RPC_FS_READ, "", fd, 0, &[0; 8]).unwrap();
        assert_eq!(&data, b"abc");
        s.fs(RPC_FS_CLOSE, "", fd, 0, &[]).unwrap();
        let _ = fs::remove_dir_all(dir);
    }
}
