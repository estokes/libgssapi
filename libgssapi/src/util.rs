use crate::error::Error;
use libgssapi_sys::{
    gss_OID, gss_OID_set, gss_OID_set_desc, gss_add_oid_set_member, gss_buffer_desc,
    gss_buffer_desc_struct, gss_buffer_t, gss_create_empty_oid_set, gss_release_buffer,
    gss_release_oid_set, gss_test_oid_set_member, size_t, OM_uint32, GSS_S_COMPLETE,
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
    pub(crate) fn as_mut_ptr(&mut self) -> gss_buffer_t {
        &mut self.0 as gss_buffer_t
    }
}

/// This represents an owned buffer we got from gssapi, it will be
/// deallocated via the library routine when it is dropped.
#[repr(transparent)]
#[allow(dead_code)]
#[derive(Debug)]
pub struct Buf(gss_buffer_desc);

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

    pub(crate) fn as_mut_ptr(&mut self) -> gss_buffer_t {
        &mut self.0 as gss_buffer_t
    }
}

struct OidSet(gss_OID_set);

impl Drop for OidSet {
    fn drop(&mut self) {
        let mut _minor = GSS_S_COMPLETE;
        let _major = unsafe {
            gss_release_oid_set(
                &mut _minor as *mut OM_uint32,
                &mut self.0 as *mut gss_OID_set,
            )
        };
        // CR estokes: What to do on error?
    }
}

impl OidSet {
    pub fn new() -> Result<OidSet, Error> {
        let mut minor = GSS_S_COMPLETE;
        let mut out = ptr::null_mut::<gss_OID_set_desc>();
        let major = unsafe {
            gss_create_empty_oid_set(
                &mut minor as *mut OM_uint32,
                &mut out as *mut gss_OID_set,
            )
        };
        if major == GSS_S_COMPLETE {
            Ok(OidSet(out))
        } else {
            Err(Error { major, minor })
        }
    }

    fn as_ptr(&mut self) -> gss_OID_set {
        self.0
    }

    pub fn add(&mut self, id: gss_OID) -> Result<(), Error> {
        let mut minor = GSS_S_COMPLETE;
        let major = unsafe {
            gss_add_oid_set_member(
                &mut minor as *mut OM_uint32,
                id,
                &mut self.0 as *mut gss_OID_set,
            )
        };
        if major == GSS_S_COMPLETE {
            Ok(())
        } else {
            Err(Error { major, minor })
        }
    }

    pub fn contains(&self, id: gss_OID) -> Result<bool, Error> {
        let mut minor = GSS_S_COMPLETE;
        let mut present = 0;
        let major = unsafe {
            gss_test_oid_set_member(
                &mut minor as *mut OM_uint32,
                id,
                self.0,
                &mut present as *mut std::os::raw::c_int,
            )
        };
        if major == GSS_S_COMPLETE {
            Ok(if present != 0 { true } else { false })
        } else {
            Err(Error { major, minor })
        }
    }
}
