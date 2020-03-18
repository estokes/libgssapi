use libgssapi_sys::{
    gss_buffer_desc, gss_buffer_desc_struct, gss_buffer_t, gss_release_buffer,
    size_t, OM_uint32, GSS_S_COMPLETE,
};
use std::{
    marker::PhantomData,
    mem,
    ops::{Deref, DerefMut, Drop},
    ptr, slice,
};

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
            value: unsafe { mem::transmute(s.as_ptr()) }, // CR estokes: bad
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
            // CR estokes: What to do if this fails?
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
}
