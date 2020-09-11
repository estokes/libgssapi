use bytes;
use libgssapi_sys::{
    gss_buffer_desc, gss_buffer_desc_struct, gss_buffer_t, gss_release_buffer, size_t,
    OM_uint32, GSS_S_COMPLETE,
};
use std::{
    ffi,
    marker::PhantomData,
    ops::{Deref, DerefMut, Drop},
    ptr, slice,
};

#[cfg(feature = "iov")]
mod iov {
    use super::*;
    use libgssapi_sys::{
        gss_iov_buffer_desc, GSS_IOV_BUFFER_FLAG_ALLOCATE, GSS_IOV_BUFFER_FLAG_ALLOCATED,
        GSS_IOV_BUFFER_TYPE_DATA, GSS_IOV_BUFFER_TYPE_EMPTY, GSS_IOV_BUFFER_TYPE_HEADER,
        GSS_IOV_BUFFER_TYPE_MECH_PARAMS, GSS_IOV_BUFFER_TYPE_PADDING,
        GSS_IOV_BUFFER_TYPE_SIGN_ONLY, GSS_IOV_BUFFER_TYPE_STREAM,
        GSS_IOV_BUFFER_TYPE_TRAILER,
    };
    const GSS_IOV_BUFFER_FLAG_MASK: u32 = 0xFFFF0000;
    #[derive(Debug, Clone, Copy)]
    pub enum GssIovType {
        Empty,
        Data,
        Header,
        MechParams,
        Trailer,
        Padding,
        Stream,
        SignOnly,
    }

    impl GssIovType {
        fn to_c(&self) -> u32 {
            match self {
                GssIovType::Empty => GSS_IOV_BUFFER_TYPE_EMPTY,
                GssIovType::Data => GSS_IOV_BUFFER_TYPE_DATA,
                GssIovType::Header => GSS_IOV_BUFFER_TYPE_HEADER,
                GssIovType::MechParams => GSS_IOV_BUFFER_TYPE_MECH_PARAMS,
                GssIovType::Trailer => GSS_IOV_BUFFER_TYPE_TRAILER,
                GssIovType::Padding => GSS_IOV_BUFFER_TYPE_PADDING,
                GssIovType::Stream => GSS_IOV_BUFFER_TYPE_STREAM,
                GssIovType::SignOnly => GSS_IOV_BUFFER_TYPE_SIGN_ONLY,
            }
        }

        fn from_c(t: u32) -> Option<Self> {
            match t & !GSS_IOV_BUFFER_FLAG_MASK {
                GSS_IOV_BUFFER_TYPE_EMPTY => Some(GssIovType::Empty),
                GSS_IOV_BUFFER_TYPE_DATA => Some(GssIovType::Data),
                GSS_IOV_BUFFER_TYPE_HEADER => Some(GssIovType::Header),
                GSS_IOV_BUFFER_TYPE_MECH_PARAMS => Some(GssIovType::MechParams),
                GSS_IOV_BUFFER_TYPE_TRAILER => Some(GssIovType::Trailer),
                GSS_IOV_BUFFER_TYPE_PADDING => Some(GssIovType::Padding),
                GSS_IOV_BUFFER_TYPE_STREAM => Some(GssIovType::Stream),
                GSS_IOV_BUFFER_TYPE_SIGN_ONLY => Some(GssIovType::SignOnly),
                _ => None,
            }
        }
    }

    /// this is a "fake" iov that exists only to ask gssapi how much space
    /// it needs for the real one.
    #[repr(transparent)]
    #[derive(Debug)]
    pub struct GssIovFake(gss_iov_buffer_desc);

    impl GssIovFake {
        /// Create a fake Iov for calls to wrap_iov_length
        pub fn new(typ: GssIovType) -> GssIovFake {
            let gss_iov = gss_iov_buffer_desc {
                type_: typ.to_c(),
                buffer: gss_buffer_desc_struct {
                    length: 0,
                    value: ptr::null_mut(),
                },
            };
            GssIovFake(gss_iov)
        }

        pub fn len(&self) -> usize {
            self.0.buffer.length as usize
        }
    }

    #[repr(transparent)]
    #[derive(Debug)]
    pub struct GssIov<'a>(gss_iov_buffer_desc, PhantomData<&'a [u8]>);

    unsafe impl<'a> Send for GssIov<'a> {}
    unsafe impl<'a> Sync for GssIov<'a> {}

    impl<'a> Drop for GssIov<'a> {
        fn drop(&mut self) {
            // check if the buffer was allocated by gssapi
            if self.0.type_ & GSS_IOV_BUFFER_FLAG_MASK & GSS_IOV_BUFFER_FLAG_ALLOCATED > 0
            {
                let mut minor = GSS_S_COMPLETE;
                let _major = unsafe {
                    gss_release_buffer(
                        &mut minor as *mut OM_uint32,
                        &mut self.0.buffer as gss_buffer_t,
                    )
                };
            }
        }
    }

    impl<'a> Deref for GssIov<'a> {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            let buf = self.0.buffer;
            unsafe { slice::from_raw_parts(buf.value.cast(), buf.length as usize) }
        }
    }

    impl<'a> DerefMut for GssIov<'a> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            let buf = self.0.buffer;
            unsafe { slice::from_raw_parts_mut(buf.value.cast(), buf.length as usize) }
        }
    }

    impl<'a> GssIov<'a> {
        /// Create a new real Iov for calls to wrap_iov.
        pub fn new(typ: GssIovType, data: &'a mut [u8]) -> GssIov<'a> {
            let gss_iov = gss_iov_buffer_desc {
                type_: typ.to_c(),
                buffer: gss_buffer_desc_struct {
                    length: data.len() as size_t,
                    value: data.as_mut_ptr().cast(),
                },
            };
            GssIov(gss_iov, PhantomData)
        }

        /// Create a new real Iov that will have necessary storage
        /// allocated as needed by gssapi.
        pub fn new_alloc(typ: GssIovType) -> GssIov<'a> {
            let gss_iov = gss_iov_buffer_desc {
                type_: typ.to_c() | GSS_IOV_BUFFER_FLAG_ALLOCATE,
                buffer: gss_buffer_desc_struct {
                    length: 0,
                    value: ptr::null_mut(),
                },
            };
            GssIov(gss_iov, PhantomData)
        }

        pub fn typ(&self) -> Option<GssIovType> {
            GssIovType::from_c(self.0.type_)
        }

        /// cast a real iov to a fake one. You need to do this for the
        /// DATA buffer for the call to `wrap_iov_length`.
        pub fn as_fake(self) -> GssIovFake {
            GssIovFake(self.0)
        }

        /// In the special case where you unwrap a token using the
        /// "stream" method, and end up with a pointer into it, you may
        /// want to know the length of the header, so you can, for
        /// example, split out just the data and send it somewhere without
        /// copying it. This function will tell you that length. Don't use
        /// it otherwise.
        pub fn header_length(&self, data: &GssIov<'a>) -> Option<usize> {
            match GssIovType::from_c(self.0.type_) {
                Some(GssIovType::Stream) => {
                    Some(data.0.buffer.value as usize - self.0.buffer.value as usize)
                }
                _ => None,
            }
        }

        pub fn len(&self) -> usize {
            self.0.buffer.length as usize
        }
    }
}

#[cfg(feature = "iov")]
pub use iov::*;

/* This type is dangerous, because we can't force C not to modify the
 * contents of the pointer, and that could have serious
 * consquences. We must use this type ONLY with gssapi functions that
 * will not modify it. */
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
            value: s.as_ptr() as *mut ffi::c_void,
        };
        BufRef(gss_buf, PhantomData)
    }
}

impl<'a> BufRef<'a> {
    pub(crate) unsafe fn to_c(&mut self) -> gss_buffer_t {
        &mut self.0 as gss_buffer_t
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
