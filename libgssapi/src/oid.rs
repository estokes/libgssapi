/// Oids are BER encoded and defined in the various RFCs. Oids are
/// horrible. This module is horrible. I'm so pleased to share my
/// horror with you.
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
    iter::{Iterator, IntoIterator, ExactSizeIterator, FromIterator},
    fmt,
    collections::HashMap,
};

// CR estokes: do I need the attributes from rfc 5587? There are loads of them.
pub static GSS_NT_USER_NAME: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01");

pub static GSS_NT_MACHINE_UID_NAME: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x02");

pub static GSS_NT_STRING_UID_NAME: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x03");

pub static GSS_NT_HOSTBASED_SERVICE: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04");

pub static GSS_NT_ANONYMOUS: Oid = Oid::from_slice(b"\x2b\x06\01\x05\x06\x03");

pub static GSS_NT_EXPORT_NAME: Oid = Oid::from_slice(b"\x2b\x06\x01\x05\x06\x04");

pub static GSS_NT_COMPOSITE_EXPORT: Oid = Oid::from_slice(b"\x2b\x06\x01\x05\x06\x06");

pub static GSS_NT_KRB5_PRINCIPAL: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x01");

pub static GSS_INQ_SSPI_SESSION_KEY: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05");

pub static GSS_INQ_NEGOEX_KEY: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x10");

pub static GSS_INQ_NEGOEX_VERIFY_KEY: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x11");

pub static GSS_MA_NEGOEX_AND_SPNEGO: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x12");

pub static GSS_SEC_CONTEXT_SASL_SSF: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x0f");

pub static GSS_MECH_KRB5: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02");

pub static GSS_MECH_IAKERB: Oid = Oid::from_slice(b"\x2b\x06\x01\x05\x02\x05");

pub static GSS_KRB5_CRED_NO_CI_FLAGS_X: Oid =
    Oid::from_slice(b"\x2a\x85\x70\x2b\x0d\x1d");

pub static GSS_KRB5_GET_CRED_IMPERSONATOR: Oid =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x0e");

pub(crate) const NO_OID: gss_OID = ptr::null_mut();
pub(crate) const NO_OID_SET: gss_OID_set = ptr::null_mut();

lazy_static! {
    static ref OIDS: HashMap<Oid, &'static str> = HashMap::from_iter([
        (GSS_NT_USER_NAME, "GSS_NT_USER_NAME"),
        (GSS_NT_MACHINE_UID_NAME, "GSS_NT_MACHINE_UID_NAME"),
        (GSS_NT_STRING_UID_NAME, "GSS_NT_STRING_UID_NAME"),
        (GSS_NT_HOSTBASED_SERVICE, "GSS_NT_HOSTBASED_SERVICE"),
        (GSS_NT_ANONYMOUS, "GSS_NT_ANONYMOUS"),
        (GSS_NT_EXPORT_NAME, "GSS_NT_EXPORT_NAME"),
        (GSS_NT_COMPOSITE_EXPORT, "GSS_NT_COMPOSITE_EXPORT"),
        (GSS_INQ_SSPI_SESSION_KEY, "GSS_INQ_SSPI_SESSION_KEY"),
        (GSS_INQ_NEGOEX_KEY, "GSS_INQ_NEGOEX_KEY"),
        (GSS_INQ_NEGOEX_VERIFY_KEY, "GSS_INQ_NEGOEX_VERIFY_KEY"),
        (GSS_MA_NEGOEX_AND_SPNEGO, "GSS_MA_NEGOEX_AND_SPNEGO"),
        (GSS_SEC_CONTEXT_SASL_SSF, "GSS_SEC_CONTEXT_SASL_SSF"),
        (GSS_MECH_KRB5, "GSS_MECH_KRB5"),
        (GSS_MECH_IAKERB, "GSS_MECH_IAKERB"),
        (GSS_NT_KRB5_PRINCIPAL, "GSS_KRB5_NT_PRINCIPAL"),
        (GSS_KRB5_CRED_NO_CI_FLAGS_X, "GSS_KRB5_CRED_NO_CI_FLAGS_X"),
        (GSS_KRB5_GET_CRED_IMPERSONATOR, "GSS_KRB5_GET_CRED_IMPERSONATOR")
    ].iter().copied());
}

/* this mirrors the C struct, but has a proper const pointer AS
SPECIFIED in the standard. This ends up being, sadly, the most
ergonomic way of wrapping the api.

Speaking of horror, here's a horrible thought. I've copied lots of
OIDs from lots of standards into this module in order to make your
life easier, and also in order to not have to run bindgen on ALL the
header files. The standard says implementations must put their oids in
static memory, and that they much be ber encoded, but it doesn't say
they can't check equality by pointer comparison. MIT Kerberos
apparantly isn't that evil, but some other implementation might be. So
if that happens I guess file a bug.
*/
/// An Oid. Did I mention I hate OIDs.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Oid {
    length: u32,
    elements: *const u8,
}

unsafe impl Sync for Oid {}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{:?}", &*self as &[u8])
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match OIDS.get(self) {
            None => write!(f, "unknown: {:?}", &*self as &[u8]),
            Some(name) => write!(f, "{}", name),
        }

    }
}

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
    pub(crate) unsafe fn from_c<'a>(ptr: gss_OID) -> Option<&'a Oid> {
        mem::transmute::<gss_OID, *const Oid>(ptr).as_ref()
    }

    pub(crate) unsafe fn to_c(&self) -> gss_OID {
        mem::transmute::<*const Oid, gss_OID>(self as *const Oid)
    }

    /// If you need to use an OID I didn't define above, then you must
    /// construct a BER encoded slice of it's components and store it
    /// in static memory (yes the standard REQUIRES that). Then you
    /// can pass it to this function and get a proper `Oid` handle. If
    /// you get the BER wrong something wonderful will happen, I just
    /// can't (won't?) say what.
    pub const fn from_slice(ber: &'static [u8]) -> Oid {
        Oid {
            length: ber.len() as u32,
            elements: ber.as_ptr(),
        }
    }
}

pub struct OidSetIter<'a> {
    current: usize,
    set: &'a OidSet,
}

impl<'a> Iterator for OidSetIter<'a> {
    type Item = &'a Oid;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current < self.len() {
            let res = Some(&self.set[self.current]);
            self.current += 1;
            res
        } else {
            None
        }
    }
}

impl<'a> ExactSizeIterator for OidSetIter<'a> {
    fn len(&self) -> usize {
        self.set.len() - self.current
    }
}

/// A set of OIDs.
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
        let len = self.len();
        if index < len {
            unsafe {
                &*mem::transmute::<gss_OID, *mut Oid>((*self.0).elements.add(index))
            }
        } else {
            panic!("index {} out of bounds count {}", index, len);
        }
    }
}

impl<'a> IntoIterator for &'a OidSet {
    type Item = &'a Oid;
    type IntoIter = OidSetIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        OidSetIter {
            current: 0,
            set: self
        }
    }
}

impl OidSet {
    /// Create an empty OID set. I don't know how this can fail unless
    /// malloc fails.
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

    pub(crate) fn from_c(ptr: gss_OID_set) -> OidSet {
        OidSet(ptr)
    }

    pub(crate) fn to_c(&self) -> gss_OID_set {
        self.0
    }
    
    /// How many oids are in this set
    pub fn len(&self) -> usize {
        unsafe { (*self.0).count as usize }
    }
    
    /// Add an OID to the set. How that can fail I don't exactly know,
    /// but it can. Oh were you looking for remove. It doesn't exist.
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

    /// Ask gssapi whether it think the specified oid is in the
    /// specified set. You can do it yourself with the Iterator, but
    /// maybe you want to ask gssapi. For some reason.
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
