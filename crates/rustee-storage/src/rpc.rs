//! Whole-file `FsRpc` over supplicant `RPC_FS_*` (fd/offset). CREATE mkdir -p on the host.
//! No mkdir opcode.

use crate::{FsRpc, StorageError};
use alloc::vec::Vec;
use rustee_proto::{
    RPC_FS_CLOSE, RPC_FS_CREATE, RPC_FS_OPEN, RPC_FS_READ, RPC_FS_REMOVE, RPC_FS_TRUNCATE,
    RPC_FS_WRITE,
};

const CHUNK: usize = 4096;

/// One FS RPC. Kernel yields `HalRpc::Fs`; tests inject an in-memory fd table.
pub trait FsClient {
    fn rpc_fs(
        &mut self,
        op: u32,
        name: &str,
        fd: u32,
        off: u32,
        data: &[u8],
    ) -> Result<(u32, Vec<u8>), StorageError>;
}

pub struct RpcFs<C> {
    pub client: C,
}

impl<C: FsClient> RpcFs<C> {
    pub fn new(client: C) -> Self {
        Self { client }
    }

    fn with_fd<T>(
        &mut self,
        path: &str,
        create: bool,
        f: impl FnOnce(&mut C, u32) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        let op = if create { RPC_FS_CREATE } else { RPC_FS_OPEN };
        let (fd, _) = self.client.rpc_fs(op, path, 0, 0, &[])?;
        let r = f(&mut self.client, fd);
        let _ = self.client.rpc_fs(RPC_FS_CLOSE, "", fd, 0, &[]);
        r
    }
}

impl<C: FsClient> FsRpc for RpcFs<C> {
    fn create(&mut self, path: &str, data: &[u8]) -> Result<(), StorageError> {
        self.with_fd(path, true, |c, fd| put(c, fd, data))
    }

    fn read(&mut self, path: &str) -> Result<Vec<u8>, StorageError> {
        self.with_fd(path, false, |c, fd| {
            let mut out = Vec::new();
            loop {
                let hint = [0u8; CHUNK];
                let off = out.len() as u32;
                let (n, chunk) = c.rpc_fs(RPC_FS_READ, "", fd, off, &hint)?;
                out.extend_from_slice(&chunk);
                if (n as usize) < CHUNK {
                    break;
                }
            }
            Ok(out)
        })
    }

    fn write(&mut self, path: &str, data: &[u8]) -> Result<(), StorageError> {
        match self.with_fd(path, false, |c, fd| put(c, fd, data)) {
            Ok(()) => Ok(()),
            Err(StorageError::NotFound) => self.with_fd(path, true, |c, fd| put(c, fd, data)),
            Err(e) => Err(e),
        }
    }

    fn delete(&mut self, path: &str) -> Result<(), StorageError> {
        self.client
            .rpc_fs(RPC_FS_REMOVE, path, 0, 0, &[])
            .map(|_| ())
    }

    fn mkdir(&mut self, _path: &str) -> Result<(), StorageError> {
        Ok(())
    }
}

fn put<C: FsClient>(c: &mut C, fd: u32, data: &[u8]) -> Result<(), StorageError> {
    let mut off = 0u32;
    while (off as usize) < data.len() {
        let end = core::cmp::min(off as usize + CHUNK, data.len());
        c.rpc_fs(RPC_FS_WRITE, "", fd, off, &data[off as usize..end])?;
        off = end as u32;
    }
    c.rpc_fs(RPC_FS_TRUNCATE, "", fd, data.len() as u32, &[])
        .map(|_| ())
}
