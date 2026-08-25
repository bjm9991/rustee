//! C TEE_Param / TEE_UUID layout and GP nibble conversion.

use crate::kernel_abi::{param_from_gp, param_type_get, Dir, Param, Uuid, PARAM_COUNT};
use crate::{TEE_ERROR_BAD_PARAMETERS, TEE_ERROR_SHORT_BUFFER, TEE_NUM_PARAMS, TeeResult};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TeeUuid {
    pub time_low: u32,
    pub time_mid: u16,
    pub time_hi_and_version: u16,
    pub clock_seq_and_node: [u8; 8],
}

impl TeeUuid {
    pub fn from_uuid(u: Uuid) -> Self {
        Self {
            time_low: u32::from_be_bytes([u.0[0], u.0[1], u.0[2], u.0[3]]),
            time_mid: u16::from_be_bytes([u.0[4], u.0[5]]),
            time_hi_and_version: u16::from_be_bytes([u.0[6], u.0[7]]),
            clock_seq_and_node: [
                u.0[8], u.0[9], u.0[10], u.0[11], u.0[12], u.0[13], u.0[14], u.0[15],
            ],
        }
    }

    pub fn to_uuid(self) -> Uuid {
        let t = self.time_low.to_be_bytes();
        let m = self.time_mid.to_be_bytes();
        let h = self.time_hi_and_version.to_be_bytes();
        Uuid([
            t[0], t[1], t[2], t[3], m[0], m[1], h[0], h[1],
            self.clock_seq_and_node[0],
            self.clock_seq_and_node[1],
            self.clock_seq_and_node[2],
            self.clock_seq_and_node[3],
            self.clock_seq_and_node[4],
            self.clock_seq_and_node[5],
            self.clock_seq_and_node[6],
            self.clock_seq_and_node[7],
        ])
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TeeIdentity {
    pub login: u32,
    pub uuid: TeeUuid,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TeeTime {
    pub seconds: u32,
    pub millis: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TeeObjectInfo {
    pub object_type: u32,
    pub object_size: u32,
    pub max_object_size: u32,
    pub object_usage: u32,
    pub data_size: usize,
    pub data_position: usize,
    pub handle_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TeeParamMemref {
    pub buffer: *mut u8,
    pub size: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TeeParamValue {
    pub a: u32,
    pub b: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TeeParam {
    pub memref: TeeParamMemref,
    pub value: TeeParamValue,
}

impl TeeParam {
    pub const fn none() -> Self {
        Self {
            value: TeeParamValue { a: 0, b: 0 },
        }
    }

    pub const fn value(a: u32, b: u32) -> Self {
        Self {
            value: TeeParamValue { a, b },
        }
    }

    pub const fn memref(buffer: *mut u8, size: usize) -> Self {
        Self {
            memref: TeeParamMemref { buffer, size },
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Identity {
    pub login: u32,
    pub uuid: Uuid,
}

pub fn params_from_gp(param_types: u32, params: *mut TeeParam) -> Result<[Param; PARAM_COUNT], TeeResult> {
    let mut out = [Param::None; PARAM_COUNT];
    for i in 0..TEE_NUM_PARAMS {
        let t = param_type_get(param_types, i);
        if params.is_null() {
            if t != 0 {
                return Err(TEE_ERROR_BAD_PARAMETERS);
            }
            continue;
        }
        let slot = unsafe { &*params.add(i) };
        let (a, b, buf, size) = unsafe {
            (
                slot.value.a,
                slot.value.b,
                slot.memref.buffer as usize,
                slot.memref.size,
            )
        };
        out[i] = param_from_gp(param_types, i, a, b, buf, size)?;
    }
    Ok(out)
}

pub fn copy_out(param_types: u32, params: *mut TeeParam, produced: &[Param; PARAM_COUNT]) {
    if params.is_null() {
        return;
    }
    for i in 0..TEE_NUM_PARAMS {
        let t = param_type_get(param_types, i);
        let slot = unsafe { &mut *params.add(i) };
        match (t, &produced[i]) {
            (2 | 3, Param::Value { a, b, dir }) if dir.is_out() => {
                slot.value.a = *a;
                slot.value.b = *b;
            }
            (6 | 7, Param::Memref { size, dir, .. }) if dir.is_out() => {
                slot.memref.size = *size;
            }
            (_, Param::Value { a, b, dir: Dir::Out | Dir::InOut }) => {
                slot.value.a = *a;
                slot.value.b = *b;
            }
            (_, Param::Memref { size, dir: Dir::Out | Dir::InOut, .. }) => {
                slot.memref.size = *size;
            }
            _ => {}
        }
    }
}

pub struct Params<'a> {
    pub types: u32,
    params: &'a mut [TeeParam; TEE_NUM_PARAMS],
}

impl<'a> Params<'a> {
    pub fn from_slice(types: u32, params: &'a mut [TeeParam; TEE_NUM_PARAMS]) -> Self {
        Self { types, params }
    }

    pub fn value(&self, i: usize) -> Option<(u32, u32)> {
        let t = param_type_get(self.types, i);
        if matches!(t, 1 | 2 | 3) {
            let v = unsafe { self.params[i].value };
            Some((v.a, v.b))
        } else {
            None
        }
    }

    pub fn set_value(&mut self, i: usize, a: u32, b: u32) {
        self.params[i].value = TeeParamValue { a, b };
    }

    pub fn memref_mut(&mut self, i: usize) -> Option<&mut [u8]> {
        let t = param_type_get(self.types, i);
        if !matches!(t, 5 | 6 | 7) {
            return None;
        }
        let m = unsafe { self.params[i].memref };
        if m.buffer.is_null() || m.size == 0 {
            Some(&mut [])
        } else {
            Some(unsafe { core::slice::from_raw_parts_mut(m.buffer, m.size) })
        }
    }

    pub fn set_memref_size(&mut self, i: usize, size: usize) {
        self.params[i].memref.size = size;
    }

    pub fn memref_size(&self, i: usize) -> Option<usize> {
        let t = param_type_get(self.types, i);
        if !matches!(t, 5 | 6 | 7) {
            return None;
        }
        Some(unsafe { self.params[i].memref.size })
    }

    /// Copy memref `src` into memref `dst`. Two `memref_mut` borrows cannot overlap.
    /// On short dest, dest size is set to the needed length and `TEE_ERROR_SHORT_BUFFER`
    /// is returned. On success dest size is the byte count copied.
    pub fn copy_memref(&mut self, src: usize, dst: usize) -> Result<usize, TeeResult> {
        if src >= TEE_NUM_PARAMS || dst >= TEE_NUM_PARAMS || src == dst {
            return Err(TEE_ERROR_BAD_PARAMETERS);
        }
        let st = param_type_get(self.types, src);
        let dt = param_type_get(self.types, dst);
        if !matches!(st, 5 | 6 | 7) || !matches!(dt, 5 | 6 | 7) {
            return Err(TEE_ERROR_BAD_PARAMETERS);
        }
        let (sp, slen) = unsafe {
            let m = self.params[src].memref;
            (m.buffer, m.size)
        };
        let (dp, dlen) = unsafe {
            let m = self.params[dst].memref;
            (m.buffer, m.size)
        };
        if slen > dlen {
            self.params[dst].memref.size = slen;
            return Err(TEE_ERROR_SHORT_BUFFER);
        }
        if slen != 0 {
            if sp.is_null() || dp.is_null() {
                return Err(TEE_ERROR_BAD_PARAMETERS);
            }
            unsafe { core::ptr::copy(sp, dp, slen) };
        }
        self.params[dst].memref.size = slen;
        Ok(slen)
    }
}
