/// Oids are BER encoded and defined in the various RFCs. Oids are
/// horrible. This module is horrible. I'm so pleased to share my
/// horror with you.
use crate::error::{Error, MajorFlags};
use libgssapi_sys::{
    GSS_S_COMPLETE, OM_uint32, gss_OID, gss_OID_desc, gss_OID_set, gss_OID_set_desc,
    gss_add_oid_set_member, gss_create_empty_oid_set, gss_release_oid_set,
    gss_test_oid_set_member,
};
use std::{
    self,
    cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd},
    collections::HashMap,
    fmt,
    hash::{Hash, Hasher},
    iter::{ExactSizeIterator, FromIterator, IntoIterator, Iterator},
    marker::PhantomData,
    ops::Deref,
    os::raw::c_int,
    ptr, slice,
    sync::LazyLock,
};

pub static GSS_NT_USER_NAME: Oid<'static> =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01");

pub static GSS_NT_MACHINE_UID_NAME: Oid<'static> =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x02");

pub static GSS_NT_STRING_UID_NAME: Oid<'static> =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x03");

pub static GSS_NT_HOSTBASED_SERVICE: Oid<'static> =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04");

pub static GSS_NT_ANONYMOUS: Oid<'static> = Oid::from_slice(b"\x2b\x06\x01\x05\x06\x03");

pub static GSS_NT_EXPORT_NAME: Oid<'static> =
    Oid::from_slice(b"\x2b\x06\x01\x05\x06\x04");

pub static GSS_NT_COMPOSITE_EXPORT: Oid<'static> =
    Oid::from_slice(b"\x2b\x06\x01\x05\x06\x06");

pub static GSS_NT_KRB5_PRINCIPAL: Oid<'static> =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x01");

pub static GSS_NT_KRB5_ENTERPRISE_NAME: Oid<'static> =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x06");

pub static GSS_INQ_SSPI_SESSION_KEY: Oid<'static> =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05");

pub static GSS_INQ_NEGOEX_KEY: Oid<'static> =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x10");

pub static GSS_INQ_NEGOEX_VERIFY_KEY: Oid<'static> =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x11");

pub static GSS_MA_NEGOEX_AND_SPNEGO: Oid<'static> =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x12");

pub static GSS_SEC_CONTEXT_SASL_SSF: Oid<'static> =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x0f");

pub static GSS_MECH_KRB5: Oid<'static> =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02");

pub static GSS_MECH_IAKERB: Oid<'static> = Oid::from_slice(b"\x2b\x06\x01\x05\x02\x05");

pub static GSS_MECH_SPNEGO: Oid<'static> = Oid::from_slice(b"\x2b\x06\x01\x05\x05\x02");

pub static GSS_KRB5_CRED_NO_CI_FLAGS_X: Oid<'static> =
    Oid::from_slice(b"\x2a\x85\x70\x2b\x0d\x1d");

pub static GSS_KRB5_GET_CRED_IMPERSONATOR: Oid<'static> =
    Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x0e");

pub(crate) const NO_OID: gss_OID = ptr::null_mut();
pub(crate) const NO_OID_SET: gss_OID_set = ptr::null_mut();

// Keyed by BER bytes (`&'static [u8]`) rather than `Oid<'static>` so
// that lookup from any `&Oid<'_>` lifetime works via the
// `Deref<Target = [u8]>` coercion.
static OIDS: LazyLock<HashMap<&'static [u8], &'static str>> = LazyLock::new(|| {
    HashMap::from_iter([
        (&*GSS_NT_USER_NAME, "GSS_NT_USER_NAME"),
        (&*GSS_NT_MACHINE_UID_NAME, "GSS_NT_MACHINE_UID_NAME"),
        (&*GSS_NT_STRING_UID_NAME, "GSS_NT_STRING_UID_NAME"),
        (&*GSS_NT_HOSTBASED_SERVICE, "GSS_NT_HOSTBASED_SERVICE"),
        (&*GSS_NT_ANONYMOUS, "GSS_NT_ANONYMOUS"),
        (&*GSS_NT_EXPORT_NAME, "GSS_NT_EXPORT_NAME"),
        (&*GSS_NT_COMPOSITE_EXPORT, "GSS_NT_COMPOSITE_EXPORT"),
        (&*GSS_INQ_SSPI_SESSION_KEY, "GSS_INQ_SSPI_SESSION_KEY"),
        (&*GSS_INQ_NEGOEX_KEY, "GSS_INQ_NEGOEX_KEY"),
        (&*GSS_INQ_NEGOEX_VERIFY_KEY, "GSS_INQ_NEGOEX_VERIFY_KEY"),
        (&*GSS_MA_NEGOEX_AND_SPNEGO, "GSS_MA_NEGOEX_AND_SPNEGO"),
        (&*GSS_SEC_CONTEXT_SASL_SSF, "GSS_SEC_CONTEXT_SASL_SSF"),
        (&*GSS_MECH_KRB5, "GSS_MECH_KRB5"),
        (&*GSS_MECH_IAKERB, "GSS_MECH_IAKERB"),
        (&*GSS_NT_KRB5_PRINCIPAL, "GSS_KRB5_NT_PRINCIPAL"),
        (&*GSS_NT_KRB5_ENTERPRISE_NAME, "GSS_KRB5_NT_ENTERPRISE_NAME"),
        (&*GSS_KRB5_CRED_NO_CI_FLAGS_X, "GSS_KRB5_CRED_NO_CI_FLAGS_X"),
        (
            &*GSS_KRB5_GET_CRED_IMPERSONATOR,
            "GSS_KRB5_GET_CRED_IMPERSONATOR",
        ),
    ])
});

/* I've copied lots of OIDs from lots of standards into this module in
 * order to make your life easier, and also in order to not have to
 * run bindgen on ALL the header files. The standard says
 * implementations must put their oids in static memory, and that they
 * much be ber encoded, but it doesn't say they can't check equality
 * by pointer comparison. MIT Kerberos apparantly isn't that evil, but
 * some other implementation might be. So if that happens I guess file
 * a bug. */
/// An Oid. Did I mention I hate OIDs.
///
/// Structurally, an `Oid` is a fat pointer (length + a pointer to BER
/// bytes). The `'a` lifetime parameter tracks the lifetime of the BER
/// bytes that the descriptor points at:
///
/// * The pre-defined constants and anything constructed via `from_slice`
///   are `Oid<'static>` — their BER bytes live forever.
/// * Mechanism OIDs returned by gssapi inquiry calls are also
///   `Oid<'static>` per RFC 2744 §3.2 (implementations must store
///   mechanism OIDs in static memory).
/// * OIDs obtained from an `OidSet` carry the set's borrow lifetime —
///   per RFC 2744 §3.4, OID set members are dynamically allocated and
///   freed with the set, so the borrow checker prevents a member from
///   outliving its set.
#[repr(transparent)]
pub struct Oid<'a>(gss_OID_desc, PhantomData<&'a [u8]>);

// Manual Clone/Copy so the impls don't carry spurious bounds on `'a`.
impl<'a> Clone for Oid<'a> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a> Copy for Oid<'a> {}

/* The data behind the descriptor is either static (for crate-defined
 * constants and gssapi-returned mechanism OIDs per RFC 2744 §3.2) or
 * owned by something whose borrow the `'a` lifetime tracks. Either way
 * the bytes are safe to read from any thread for the duration of `'a`. */
unsafe impl<'a> Send for Oid<'a> {}
unsafe impl<'a> Sync for Oid<'a> {}

impl<'a> fmt::Debug for Oid<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let bytes: &[u8] = self;
        match OIDS.get(bytes) {
            None => write!(f, "{:?}", bytes),
            Some(name) => write!(f, "{}", name),
        }
    }
}

impl<'a> fmt::Display for Oid<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        fmt::Debug::fmt(self, f)
    }
}

impl<'a> Deref for Oid<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        if self.0.elements.is_null() || self.0.length == 0 {
            &[]
        } else {
            unsafe {
                slice::from_raw_parts(self.0.elements.cast(), self.0.length as usize)
            }
        }
    }
}

// Cross-lifetime equality / ordering. Two OIDs are equal if their BER
// bytes are equal, regardless of where the storage lives.
impl<'a, 'b> PartialEq<Oid<'b>> for Oid<'a> {
    fn eq(&self, other: &Oid<'b>) -> bool {
        (self as &[u8]) == (other as &[u8])
    }
}

impl<'a> Eq for Oid<'a> {}

impl<'a, 'b> PartialOrd<Oid<'b>> for Oid<'a> {
    fn partial_cmp(&self, other: &Oid<'b>) -> Option<Ordering> {
        (self as &[u8]).partial_cmp(other as &[u8])
    }
}

impl<'a> Ord for Oid<'a> {
    fn cmp(&self, other: &Oid<'a>) -> Ordering {
        (self as &[u8]).cmp(other as &[u8])
    }
}

impl<'a> Hash for Oid<'a> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        (self as &[u8]).hash(state)
    }
}

impl Oid<'static> {
    /// Build a static `Oid` from a static slice of BER-encoded bytes.
    /// The spec requires every OID to be backed by static memory, which
    /// is what the `&'static [u8]` argument enforces here.
    pub const fn from_slice(ber: &'static [u8]) -> Oid<'static> {
        let length = ber.len() as OM_uint32;
        let elements = ber.as_ptr() as *mut std::ffi::c_void;
        Oid(gss_OID_desc { length, elements }, PhantomData)
    }

    /// Wrap a raw `gss_OID` returned by gssapi as a static `Oid`. Use
    /// this only for OIDs that the spec guarantees are static — i.e.
    /// mechanism OIDs returned by `gss_inquire_context`,
    /// `gss_inquire_cred`, `gss_indicate_mechs`, etc.
    ///
    /// Panics if `ptr` is null. A null `gss_OID` is never a valid OID;
    /// if gssapi returned `GSS_S_COMPLETE` and still wrote null, the
    /// implementation has violated the spec and there is no sensible
    /// value to return.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a `gss_OID_desc` whose `elements` buffer lives
    /// for the lifetime of the program. RFC 2744 §3.2 requires mechanism
    /// OIDs to be stored in static memory, so this holds for mechanism
    /// OIDs by spec; it does NOT hold for OIDs living inside a
    /// `gss_OID_set`, which are freed with the set.
    #[allow(dead_code)]
    pub(crate) unsafe fn from_c(ptr: gss_OID) -> Oid<'static> {
        assert!(
            !ptr.is_null(),
            "Oid::from_c: gssapi returned a null OID pointer"
        );
        Oid(unsafe { *ptr }, PhantomData)
    }
}

impl<'a> Oid<'a> {
    pub(crate) unsafe fn to_c(&self) -> gss_OID {
        self as *const Oid<'a> as gss_OID
    }

    /// Wrap a raw `gss_OID_desc` by value with a caller-supplied
    /// lifetime. Prefer `Oid::from_slice` for compile-time-known OIDs;
    /// this exists for wrapping a descriptor obtained from elsewhere
    /// (e.g. another FFI binding).
    ///
    /// # Safety
    ///
    /// `desc.elements` must point to a valid BER-encoded OID of
    /// `desc.length` bytes, and that memory must remain valid and
    /// immutable for the entire lifetime `'a`.
    pub unsafe fn from_raw_desc(desc: gss_OID_desc) -> Oid<'a> {
        Oid(desc, PhantomData)
    }

    /// Promote this `Oid<'a>` to `Oid<'static>` — for cases where you
    /// know the BER bytes outlive the borrow that gave you this `Oid`
    /// (e.g. you've stashed them somewhere persistent, or the
    /// implementation actually keeps them static even though the type
    /// system was conservative).
    ///
    /// # Safety
    ///
    /// The BER bytes pointed at by this `Oid` must remain valid for the
    /// lifetime of the program. Per RFC 2744 §3.4, OID set members are
    /// dynamically allocated and freed when the set is released —
    /// promoting a set member without first copying its bytes elsewhere
    /// is a use-after-free on every subsequent dereference of the
    /// returned `Oid`.
    pub unsafe fn assume_static(self) -> Oid<'static> {
        Oid(self.0, PhantomData)
    }
}

pub struct OidSetIter<'a> {
    current: usize,
    set: &'a OidSet,
}

impl<'a> Iterator for OidSetIter<'a> {
    type Item = Oid<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let res = self.set.get(self.current);
        if res.is_some() {
            self.current += 1;
        }
        res
    }
}

impl<'a> ExactSizeIterator for OidSetIter<'a> {
    fn len(&self) -> usize {
        self.set.len() - self.current
    }
}

/// A set of OIDs.
pub struct OidSet(gss_OID_set);

// these are safe if we assume that the gssapi calls we pass oid sets
// to make copies if they need to retain the sets. They'd be crazy not
// to, given that the user will probably free the set soon after
// making the call.
unsafe impl Send for OidSet {}
unsafe impl Sync for OidSet {}

impl Drop for OidSet {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let mut _minor = GSS_S_COMPLETE;
            let _major = unsafe {
                gss_release_oid_set(
                    &mut _minor as *mut OM_uint32,
                    &mut self.0 as *mut gss_OID_set,
                )
            };
        }
    }
}

impl<'a> IntoIterator for &'a OidSet {
    type Item = Oid<'a>;
    type IntoIter = OidSetIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        OidSetIter {
            current: 0,
            set: self,
        }
    }
}

impl fmt::Debug for OidSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        fmt::Debug::fmt(&self.into_iter().collect::<Vec<_>>(), f)
    }
}

impl Default for OidSet {
    fn default() -> Self {
        Self::new()
    }
}

impl OidSet {
    /// Create an empty OID set. Wraps `GSS_C_NO_OID_SET` (a null pointer);
    /// the underlying gssapi set is lazily allocated on the first `add`.
    pub fn new() -> OidSet {
        OidSet(ptr::null_mut())
    }

    /// Create an OID set containing exactly `id`. Equivalent to `new()`
    /// followed by a single `add`, which is by far the most common way a
    /// set gets built (e.g. a one-mech `desired_mechs`).
    pub fn singleton(id: Oid<'_>) -> Result<OidSet, Error> {
        let mut set = OidSet::new();
        set.add(id)?;
        Ok(set)
    }

    /// Wrap a raw `gss_OID_set` returned by gssapi. A null pointer is
    /// permitted — gssapi uses `GSS_C_NO_OID_SET` (NULL) as the canonical
    /// "no preference / empty set" sentinel, and `OidSet`'s methods treat
    /// a null inner pointer as an empty set.
    #[allow(dead_code)]
    pub(crate) unsafe fn from_c(ptr: gss_OID_set) -> OidSet {
        OidSet(ptr)
    }

    pub(crate) unsafe fn to_c(&self) -> gss_OID_set {
        self.0
    }

    /// How many oids are in this set. A null inner pointer
    /// (`GSS_C_NO_OID_SET`) is treated as empty.
    pub fn len(&self) -> usize {
        if self.0.is_null() {
            0
        } else {
            unsafe { (*self.0).count as usize }
        }
    }

    /// Return the `i`th OID in the set, or `None` if out of range. The
    /// returned `Oid` borrows from the set (its lifetime is tied to
    /// `&self`) — per RFC 2744 §3.4, OID set members are freed with the
    /// set, so the borrow checker prevents the returned `Oid` from
    /// outliving its source.
    pub fn get<'a>(&'a self, i: usize) -> Option<Oid<'a>> {
        if i >= self.len() {
            return None;
        }
        let desc = unsafe { *(*self.0).elements.add(i) };
        Some(Oid(desc, PhantomData))
    }

    /// Add an OID to the set. If this `OidSet` was constructed from
    /// `GSS_C_NO_OID_SET` (null inner pointer), a fresh empty set is
    /// allocated first.
    pub fn add(&mut self, id: Oid<'_>) -> Result<(), Error> {
        if self.0.is_null() {
            let mut minor = GSS_S_COMPLETE;
            let mut out = ptr::null_mut::<gss_OID_set_desc>();
            let major = unsafe {
                gss_create_empty_oid_set(
                    &mut minor as *mut OM_uint32,
                    &mut out as *mut gss_OID_set,
                )
            };
            if major != GSS_S_COMPLETE {
                return Err(Error {
                    major: MajorFlags::from_bits_retain(major),
                    minor,
                });
            }
            self.0 = out;
        }
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
            Err(Error {
                major: MajorFlags::from_bits_retain(major),
                minor,
            })
        }
    }

    /// Ask gssapi whether it thinks the specified oid is in the
    /// specified set. A null inner pointer (`GSS_C_NO_OID_SET`) is
    /// treated as empty and short-circuits to `Ok(false)`.
    pub fn contains(&self, id: Oid<'_>) -> Result<bool, Error> {
        if self.0.is_null() {
            return Ok(false);
        }
        let mut minor = GSS_S_COMPLETE;
        let mut present = 0;
        let major = unsafe {
            gss_test_oid_set_member(
                &mut minor as *mut OM_uint32,
                id.to_c(),
                self.0,
                &mut present as *mut c_int,
            )
        };
        if major == GSS_S_COMPLETE {
            Ok(if present != 0 { true } else { false })
        } else {
            Err(Error {
                major: MajorFlags::from_bits_retain(major),
                minor,
            })
        }
    }
}
