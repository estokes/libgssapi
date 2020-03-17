/// Oids are BER encoded and defined in the various RFCs
use crate::error::Error;
use libgssapi_sys::{
    gss_OID, gss_OID_desc, gss_OID_set, gss_OID_set_desc, gss_add_oid_set_member,
    gss_create_empty_oid_set, gss_release_oid_set, gss_test_oid_set_member, OM_uint32,
    GSS_S_COMPLETE,
};
use std::{
    self,
    cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd},
    hash::{Hash, Hasher},
    mem,
    ops::{Deref, Index},
    slice,
    ptr,
};

// CR estokes: do I need the attributes from rfc 5587? There are loads of them.
pub static GSS_C_NT_USER_NAME: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01");

pub static GSS_C_NT_MACHINE_UID_NAME: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x02");

pub static GSS_C_NT_STRING_UID_NAME: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x03");

pub static GSS_C_NT_HOSTBASED_SERVICE: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04");

pub static GSS_C_NT_ANONYMOUS: Oid = Oid::from_slice(b"\x2b\x06\01\x05\x06\x03");

pub static GSS_C_NT_EXPORT_NAME: Oid = Oid::from_slice(b"\x2b\x06\x01\x05\x06\x04");

pub static GSS_C_NT_COMPOSITE_EXPORT: Oid = Oid::from_slice(b"\x2b\x06\x01\x05\x06\x06");

pub static GSS_C_INQ_SSPI_SESSION_KEY: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05");

pub static GSS_C_INQ_NEGOEX_KEY: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x10");

pub static GSS_C_INQ_NEGOEX_VERIFY_KEY: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x11");

pub static GSS_C_MA_NEGOEX_AND_SPNEGO: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x12");

pub static GSS_SEC_CONTEXT_SASL_SSF_OID: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x0f");

pub static GSS_MECH_KRB5_OID: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02");

pub static GSS_MECH_IAKERB_OID: Oid = Oid::from_slice(b"\x2b\x06\x01\x05\x02\x05");

pub static GSS_KRB5_NT_PRINCIPAL_NAME: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x01");

pub static GSS_KRB5_CRED_NO_CI_FLAGS_X: Oid =
    Oid::from_slice(b"\x2a\x85\x70\x2b\x0d\x1d");

pub static GSS_KRB5_GET_CRED_IMPERSONATOR: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x0e");

// this mirrors the C struct, but has a proper const pointer AS
// SPECIFIED in the standard. This ends up being, sadly, the most
// ergonomic way of wrapping the api.
#[repr(C)]
pub struct Oid {
    length: u32,
    elements: *const u8,
}

unsafe impl Sync for Oid {}

impl Deref for Oid {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { slice::from_raw_parts(self.elements, self.length as usize) }
    }
}

impl PartialEq for Oid {
    fn eq(&self, other: &Oid) -> bool {
        &*self == &*other
    }
}

impl Eq for Oid {}

impl PartialOrd for Oid {
    fn partial_cmp(&self, other: &Oid) -> Option<Ordering> {
        (&*self as &[u8]).partial_cmp(&*other as &[u8])
    }
}

impl Ord for Oid {
    fn cmp(&self, other: &Oid) -> Ordering {
        (&*self as &[u8]).cmp(&*other as &[u8])
    }
}

impl Hash for Oid {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        (&*self as &[u8]).hash(state)
    }
}

impl From<gss_OID_desc> for Oid {
    fn from(oid: gss_OID_desc) -> Self {
        Oid {
            length: oid.length,
            elements: unsafe { mem::transmute::<*mut std::ffi::c_void, _>(oid.elements) },
        }
    }
}

impl Oid {
    pub(crate) fn from_c<'a>(ptr: gss_OID) -> Option<&'a Oid> {
        unsafe { mem::transmute::<gss_OID, *const Oid>(ptr).as_ref() }
    }

    pub(crate) fn to_c(&self) -> gss_OID {
        unsafe { mem::transmute::<*const Oid, gss_OID>(self as *const Oid) }
    }

    pub const fn from_slice(ber: &'static [u8]) -> Oid {
        Oid {
            length: ber.len() as u32,
            elements: ber.as_ptr(),
        }
    }
}

pub struct OidSet(gss_OID_set);

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

impl Index<usize> for OidSet {
    type Output = Oid;

    fn index(&self, index: usize) -> &Self::Output {
        unsafe {
            let count = (*self.0).count;
            if index < count as usize {
                &*mem::transmute::<gss_OID, *mut Oid>((*self.0).elements.add(index))
            } else {
                panic!("index {} out of bounds count {}", index, count);
            }
        }
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

    pub(crate) fn as_ptr(&mut self) -> gss_OID_set {
        self.0
    }

    pub fn add(&mut self, id: &Oid) -> Result<(), Error> {
        let mut minor = GSS_S_COMPLETE;
        let major = unsafe {
            gss_add_oid_set_member(
                &mut minor as *mut OM_uint32,
                id.to_c(),
                &mut self.0 as *mut gss_OID_set,
            )
        };
        if major == GSS_S_COMPLETE {
            Ok(())
        } else {
            Err(Error { major, minor })
        }
    }

    pub fn contains(&self, id: &Oid) -> Result<bool, Error> {
        let mut minor = GSS_S_COMPLETE;
        let mut present = 0;
        let major = unsafe {
            gss_test_oid_set_member(
                &mut minor as *mut OM_uint32,
                id.to_c(),
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
