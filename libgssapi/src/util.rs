use crate::error::Error;
use bytes;
use libgssapi_sys::{
    gss_buffer_desc, gss_buffer_desc_struct, gss_buffer_t, gss_iov_buffer_desc,
    gss_iov_buffer_desc_struct, gss_release_buffer, size_t, OM_uint32, GSS_S_COMPLETE,
};
pub use libgssapi_sys::{
    GSS_IOV_BUFFER_FLAG_ALLOCATE, GSS_IOV_BUFFER_FLAG_ALLOCATED,
    GSS_IOV_BUFFER_FLAG_MASK, GSS_IOV_BUFFER_TYPE_DATA, GSS_IOV_BUFFER_TYPE_EMPTY,
    GSS_IOV_BUFFER_TYPE_HEADER, GSS_IOV_BUFFER_TYPE_MECH_PARAMS,
    GSS_IOV_BUFFER_TYPE_MIC_TOKEN, GSS_IOV_BUFFER_TYPE_PADDING,
    GSS_IOV_BUFFER_TYPE_SIGN_ONLY, GSS_IOV_BUFFER_TYPE_STREAM,
    GSS_IOV_BUFFER_TYPE_TRAILER,
};
use std::{
    marker::PhantomData,
    mem,
    ops::{Deref, DerefMut, Drop},
    ptr, slice,
};

// This type is dangerous, because we can't force C not to modify the
// contents of the pointer, and that could have serious
// consquences. You must use this type ONLY with gssapi functions that
// will not modify it.
#[repr(transparent)]
#[derive(Debug)]
pub(crate) struct BufRef<'a>(gss_buffer_desc_struct, PhantomData<&'a [u8]>);

unsafe impl<'a> Send for BufRef<'a> {}
unsafe impl<'a> Sync for BufRef<'a> {}

impl<'a> Deref for BufRef<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { slice::from_raw_parts(self.0.value.cast(), self.0.length as usize) }
    }
}

impl<'a> From<&'a [u8]> for BufRef<'a> {
    fn from(s: &[u8]) -> Self {
        let gss_buf = gss_buffer_desc_struct {
            length: s.len() as size_t,
            value: unsafe { mem::transmute::<*const u8, *mut u8>(s.as_ptr()) },
        };
        BufRef(gss_buf, PhantomData)
    }
}

impl<'a> BufRef<'a> {
    pub(crate) unsafe fn to_c(&mut self) -> gss_buffer_t {
        &mut self.0 as gss_buffer_t
    }
}

struct GssIovFake;
struct GssIovReal;

#[repr(transparent)]
#[derive(Debug)]
pub struct GssIov<'a, K>(gss_iov_buffer_desc, PhantomData<&'a K>);

unsafe impl<'a, K> Send for GssIov<'a, K> {}
unsafe impl<'a, K> Sync for GssIov<'a, K> {}

impl<'a> Drop for GssIov<'a, GssIovReal> {
    fn drop(&mut self) {
        // check if the buffer was allocated by gssapi
        if self.0.type_ & GSS_IOV_BUFFER_FLAG_MASK & GSS_IOV_BUFFER_FLAG_ALLOCATED > 0 {
            let mut minor = GSS_S_COMPLETE;
            let _major = unsafe {
                gss_release_buffer(
                    &mut minor as *mut OM_uint32,
                    &mut self.0.buffer as gss_buffer_t
                )
            };
        }
    }
}

impl<'a> Deref for GssIov<'a, GssIovReal> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let buf = self.0.buffer;
        unsafe { slice::from_raw_parts(buf.value.cast(), buf.length as usize) }
    }
}

impl<'a> DerefMut for GssIov<'a, GssIovReal> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let buf = self.0.buffer;
        unsafe { slice::from_raw_parts_mut(buf.value, buf.length as usize) }
    }
}

impl<'a> From<&'a mut [u8]> for GssIov<'a, GssIovReal> {
    fn from(s: &mut [u8]) -> Self {
        let gss_iov = gss_iov_buffer_desc {
            type_: 0,
            buffer: gss_buffer_desc_struct {
                length: s.len() as size_t,
                value: s.as_mut_ptr(),
            },
        };
        GssIov(gss_iov, PhantomData)
    }
}

impl<'a, K> GssIov<'a, K> {
    /// Create a fake Iov for calls to wrap_iov_length
    pub fake() -> GssIov<'a, GssIovFake> {
        let gss_iov = gss_iov_buffer_desc {
            type_: 0,
            buffer: gss_buffer_desc_struct {
                length: 0
                value: ptr::null_mut()
            }
        };
        GssIov(gss_iov, PhantomData)
    }

    pub typ(&self) -> &u32 {
        &self.0.type_
    }

    pub typ_mut(&mut self) -> &mut u32 {
        &mut self.0.type_
    }

    pub len(&self) -> usize {
        self.0.buffer.length as usize
    }
}

/// This represents an owned buffer we got from gssapi, it will be
/// deallocated via the library routine when it is dropped.
#[repr(transparent)]
#[allow(dead_code)]
#[derive(Debug)]
pub struct Buf(gss_buffer_desc);

unsafe impl Send for Buf {}
unsafe impl Sync for Buf {}

impl Deref for Buf {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { slice::from_raw_parts(self.0.value.cast(), self.0.length as usize) }
    }
}

impl DerefMut for Buf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { slice::from_raw_parts_mut(self.0.value.cast(), self.0.length as usize) }
    }
}

impl Drop for Buf {
    fn drop(&mut self) {
        if !self.0.value.is_null() {
            let mut minor = GSS_S_COMPLETE;
            let _major = unsafe {
                gss_release_buffer(
                    &mut minor as *mut OM_uint32,
                    &mut self.0 as gss_buffer_t,
                )
            };
        }
    }
}

impl Buf {
    pub(crate) fn empty() -> Buf {
        Buf(gss_buffer_desc {
            length: 0 as size_t,
            value: ptr::null_mut(),
        })
    }

    pub(crate) unsafe fn to_c(&mut self) -> gss_buffer_t {
        &mut self.0 as gss_buffer_t
    }

    /// Wrap this bytes in a structure that implements `bytes::Buf`
    pub fn to_bytes(self) -> GssBytes {
        GssBytes { pos: 0, buf: self }
    }
}

#[derive(Debug)]
pub struct GssBytes {
    pos: usize,
    buf: Buf,
}

impl bytes::Buf for GssBytes {
    fn remaining(&self) -> usize {
        self.buf.0.length as usize - self.pos
    }

    fn bytes(&self) -> &[u8] {
        &((*self.buf)[self.pos..])
    }

    fn advance(&mut self, cnt: usize) {
        let rem = self.remaining();
        if cnt > rem {
            panic!(
                "advancing {} would overrun the remaining buffer {}",
                cnt, rem
            );
        } else {
            self.pos += cnt;
        }
    }
}

impl GssBytes {
    /// Consume the GssBytes and return the inner buffer
    pub fn into_inner(self) -> Buf {
        self.buf
    }
}
