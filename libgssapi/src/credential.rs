use crate::{
    error::{gss_error, Error, MajorFlags},
    name::Name,
    oid::{OidSet, NO_OID_SET},
    util::BufRef
};
#[cfg(feature = "s4u")]
use crate::{
    oid::{GSS_KRB5_GET_CRED_IMPERSONATOR, GSS_NT_HOSTBASED_SERVICE},
    util::BufSet,
};
use libgssapi_sys::{gss_OID_set, gss_acquire_cred, gss_acquire_cred_with_password, gss_cred_id_struct, gss_cred_id_t, gss_cred_usage_t, gss_inquire_cred, gss_name_struct, gss_name_t, gss_release_cred, gss_store_cred, OM_uint32, GSS_C_ACCEPT, GSS_C_BOTH, GSS_C_INITIATE, GSS_S_COMPLETE, _GSS_C_INDEFINITE};
#[cfg(feature = "s4u")]
use libgssapi_sys::{
    gss_acquire_cred_impersonate_name, gss_inquire_cred_by_oid,
    gss_key_value_element_desc, gss_key_value_set_desc, gss_store_cred_into,
};
#[cfg(feature = "s4u")]
use std::ffi::{CStr, CString};
use std::{fmt, ptr, time::Duration};
use std::ffi::c_int;
use std::sync::Arc;
use crate::oid::{Oid, NO_OID};

pub(crate) const NO_CRED: gss_cred_id_t = ptr::null_mut();

#[derive(Debug)]
pub struct CredInfo {
    pub name: Name,
    pub proxy: Option<Name>,
    pub lifetime: Duration,
    pub usage: CredUsage,
    pub mechanisms: OidSet,
}

struct CredInfoC {
    name: Option<gss_name_t>,
    lifetime: Option<u32>,
    usage: Option<i32>,
    mechanisms: Option<gss_OID_set>,
}

impl CredInfoC {
    fn empty() -> CredInfoC {
        CredInfoC {
            name: None,
            lifetime: None,
            usage: None,
            mechanisms: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CredUsage {
    Accept,
    Initiate,
    Both,
}

impl CredUsage {
    fn from_c(c: i32) -> Result<Self, Error> {
        match c as u32 {
            GSS_C_BOTH => Ok(CredUsage::Both),
            GSS_C_INITIATE => Ok(CredUsage::Initiate),
            GSS_C_ACCEPT => Ok(CredUsage::Accept),
            _ => Err(Error {
                    major: MajorFlags::GSS_S_FAILURE,
                    minor: 0,
                })
        }
    }

    fn to_c(&self) -> u32 {
        match self {
            CredUsage::Both => GSS_C_BOTH,
            CredUsage::Initiate => GSS_C_INITIATE,
            CredUsage::Accept => GSS_C_ACCEPT,
        }
    }
}

/// gssapi credentials.
#[derive(Clone)]
pub struct Cred(Arc<InnerCred>);
impl From<gss_cred_id_t> for Cred {
    fn from(id: gss_cred_id_t) -> Self {
        Cred(Arc::new(InnerCred(id)))
    }
}
struct InnerCred(gss_cred_id_t);

impl Drop for InnerCred {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let mut minor = GSS_S_COMPLETE;
            let _major = unsafe {
                gss_release_cred(
                    &mut minor as *mut OM_uint32,
                    &mut self.0 as *mut gss_cred_id_t,
                )
            };
        }
    }
}

unsafe impl Send for InnerCred {}
unsafe impl Sync for InnerCred {}

impl fmt::Debug for Cred {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self.info() {
            Err(e) => write!(f, "error getting credential info {}", e),
            Ok(ifo) => write!(f, "{:?}", ifo),
        }
    }
}

impl Cred {
    /// Acquire gssapi credentials for `name` or the default name,
    /// lasting for `time_req` or as long as possible, for the purpose
    /// of `usage`, and for use with `desired_mechs` or the default
    /// mechanism.
    pub fn acquire(
        name: Option<&Name>,
        time_req: Option<Duration>,
        usage: CredUsage,
        desired_mechs: Option<&OidSet>,
    ) -> Result<Cred, Error> {
        let time_req = time_req
            .map(|d| d.as_secs() as u32)
            .unwrap_or(_GSS_C_INDEFINITE);
        let mut minor = GSS_S_COMPLETE;
        let usage = usage.to_c();
        let mut cred = ptr::null_mut::<gss_cred_id_struct>();
        let major = unsafe {
            gss_acquire_cred(
                &mut minor as *mut OM_uint32,
                match name {
                    None => ptr::null_mut::<gss_name_struct>(),
                    Some(n) => n.to_c(),
                },
                time_req,
                match desired_mechs {
                    None => NO_OID_SET,
                    Some(desired_mechs) => desired_mechs.to_c(),
                },
                usage as gss_cred_usage_t,
                &mut cred as *mut gss_cred_id_t,
                ptr::null_mut::<gss_OID_set>(),
                ptr::null_mut::<OM_uint32>(),
            )
        };
        if major == GSS_S_COMPLETE {
            Ok(Cred::from(cred))
        } else {
            Err(Error {
                major: MajorFlags::from_bits_retain(major),
                minor,
            })
        }
    }

    pub fn pass_acquire(
        name: Option<&Name>,
        password: &str,
        time_req: Option<Duration>,
        usage: CredUsage,
        desired_mechs: Option<&OidSet>,
    ) -> Result<Cred, Error> {
        let time_req = time_req
            .map(|d| d.as_secs() as u32)
            .unwrap_or(_GSS_C_INDEFINITE);
        let mut minor = GSS_S_COMPLETE;
        let usage = usage.to_c();
        let mut cred = ptr::null_mut::<gss_cred_id_struct>();
        let major = unsafe {
            gss_acquire_cred_with_password(
                &mut minor as *mut OM_uint32,
                match name {
                    None => ptr::null_mut::<gss_name_struct>(),
                    Some(n) => n.to_c(),
                },
                BufRef::from(password.as_bytes()).to_c(),
                time_req,
                match desired_mechs {
                    None => NO_OID_SET,
                    Some(desired_mechs) => desired_mechs.to_c(),
                },
                usage as gss_cred_usage_t,
                &mut cred as *mut gss_cred_id_t,
                ptr::null_mut::<gss_OID_set>(),
                ptr::null_mut::<OM_uint32>(),
            )
        };
        if major == GSS_S_COMPLETE {
            Ok(Cred::from(cred))
        } else {
            Err(Error {
                major: MajorFlags::from_bits_retain(major),
                minor,
            })
        }
    }

    #[cfg(feature = "s4u")]
    pub fn impersonate(
        &self,
        name: &Name,
        time_req: Option<Duration>,
        usage: CredUsage,
        desired_mechs: Option<&OidSet>,
    ) -> Result<Cred, Error> {
        let time_req = time_req
            .map(|d| d.as_secs() as u32)
            .unwrap_or(_GSS_C_INDEFINITE);
        let mut minor = GSS_S_COMPLETE;
        let usage = usage.to_c();
        let mut cred = ptr::null_mut::<gss_cred_id_struct>();
        let major = unsafe {
            gss_acquire_cred_impersonate_name(
                &mut minor as *mut OM_uint32,
                self.to_c(),
                name.to_c(),
                time_req,
                match desired_mechs {
                    None => NO_OID_SET,
                    Some(desired_mechs) => desired_mechs.to_c(),
                },
                usage as gss_cred_usage_t,
                &mut cred as *mut gss_cred_id_t,
                ptr::null_mut::<gss_OID_set>(),
                ptr::null_mut::<OM_uint32>(),
            )
        };
        if major == GSS_S_COMPLETE {
            Ok(Cred::from(cred))
        } else {
            Err(Error {
                major: MajorFlags::from_bits_retain(major),
                minor,
            })
        }
    }

    #[cfg(feature = "s4u")]
    pub fn store(
        &self,
        ccache: &str,
        overwrite: bool,
        default: bool,
        usage: CredUsage,
        desired_mech: Option<&Oid>,
    ) -> Result<(), Error> {
        let mut minor = GSS_S_COMPLETE;
        let usage = usage.to_c();
        let ccache = CString::new(ccache).map_err(|_| Error {
            major: MajorFlags::GSS_S_CALL_INACCESSIBLE_READ | MajorFlags::GSS_S_BAD_NAME,
            minor: 0,
        })?;
        let mut elems = gss_key_value_element_desc {
            key: CStr::from_bytes_with_nul(b"ccache\0").unwrap().as_ptr(),
            value: ccache.as_ptr(),
        };
        let store = gss_key_value_set_desc {
            count: 1,
            elements: &mut elems,
        };
        let major = unsafe {
            gss_store_cred_into(
                &mut minor as *mut OM_uint32,
                self.to_c(),
                usage as gss_cred_usage_t,
                match desired_mech {
                    None => NO_OID,
                    Some(desired_mechs) => desired_mechs.to_c(),
                },
                overwrite as u32,
                default as u32,
                &store,
                ptr::null_mut::<gss_OID_set>(),
                ptr::null_mut::<gss_cred_usage_t>(),
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

    /// Copies credentials into default credentials cache.
    pub fn gss_store(
        &self,
        overwrite: bool,
        default: bool,
        usage: CredUsage,
        desired_mech: Option<&Oid>,
    ) -> Result<(OidSet, CredUsage), Error> {
        let mut minor = GSS_S_COMPLETE;
        let elements_stored = OidSet::new()?;
        let res_usage = CredUsage::Both.to_c();
        let major = unsafe {
            gss_store_cred(
                &mut minor as *mut OM_uint32,
                self.to_c(),
                usage.to_c() as gss_cred_usage_t,
                match desired_mech {
                    None => NO_OID,
                    Some(desired_mechs) => desired_mechs.to_c(),
                },
                overwrite as u32,
                default as u32,
                &mut elements_stored.to_c(),
                &mut (res_usage as c_int) as *mut gss_cred_usage_t,
            )
        };
        if major == GSS_S_COMPLETE {
            Ok((elements_stored, CredUsage::from_c(res_usage as i32)?))
        } else {
            Err(Error {
                major: MajorFlags::from_bits_retain(major),
                minor,
            })
        }
    }

    pub(crate) unsafe fn from_c(cred: gss_cred_id_t) -> Cred {
        Cred::from(cred)
    }

    pub(crate) unsafe fn to_c(&self) -> gss_cred_id_t {
        self.0.0
    }

    unsafe fn info_c(&self, mut ifo: CredInfoC) -> Result<CredInfoC, Error> {
        let mut minor: u32 = 0;
        let major = gss_inquire_cred(
            &mut minor as *mut OM_uint32,
            self.0.0,
            match ifo.name {
                None => ptr::null_mut::<gss_name_t>(),
                Some(ref mut n) => n as *mut gss_name_t,
            },
            match ifo.lifetime {
                None => ptr::null_mut::<u32>(),
                Some(ref mut l) => l as *mut OM_uint32,
            },
            match ifo.usage {
                None => ptr::null_mut::<i32>(),
                Some(ref mut u) => u as *mut gss_cred_usage_t,
            },
            match ifo.mechanisms {
                None => ptr::null_mut::<gss_OID_set>(),
                Some(ref mut s) => s as *mut gss_OID_set,
            },
        );
        if gss_error(major) > 0 {
            // make sure we free anything that was successfully built
            if let Some(n) = ifo.name {
                Name::from_c(n);
            }
            if let Some(s) = ifo.mechanisms {
                OidSet::from_c(s);
            }
            Err(Error {
                major: MajorFlags::from_bits_retain(major),
                minor,
            })
        } else {
            Ok(ifo)
        }
    }

    /// Return all the information associated with this credential
    pub fn info(&self) -> Result<CredInfo, Error> {
        unsafe {
            let c = self.info_c(CredInfoC {
                name: Some(ptr::null_mut()),
                lifetime: Some(0),
                usage: Some(0),
                mechanisms: Some(ptr::null_mut()),
            })?;
            Ok(CredInfo {
                name: Name::from_c(c.name.unwrap()),
                proxy: self.proxy()?,
                lifetime: Duration::from_secs(c.lifetime.unwrap() as u64),
                usage: CredUsage::from_c(c.usage.unwrap())?,
                mechanisms: OidSet::from_c(c.mechanisms.unwrap()),
            })
        }
    }

    /// Return the name associated with this credential
    pub fn name(&self) -> Result<Name, Error> {
        unsafe {
            let c = self.info_c(CredInfoC {
                name: Some(ptr::null_mut()),
                ..CredInfoC::empty()
            })?;
            Ok(Name::from_c(c.name.unwrap()))
        }
    }

    /// Return the proxy service associated with this credential
    pub fn proxy(&self) -> Result<Option<Name>, Error> {
        #[cfg(feature = "s4u")]
        unsafe {
            let mut out = BufSet::empty();
            let mut minor: u32 = 0;
            let major = gss_inquire_cred_by_oid(
                &mut minor as *mut OM_uint32,
                self.0.0,
                GSS_KRB5_GET_CRED_IMPERSONATOR.to_c(),
                out.to_c(),
            );
            if gss_error(major) > 0 {
                Err(Error {
                    major: MajorFlags::from_bits_retain(major),
                    minor,
                })
            } else {
                if let Some(name) = out.first() {
                    Name::new(name, Some(&GSS_NT_HOSTBASED_SERVICE)).map(Into::into)
                } else {
                    Ok(None)
                }
            }
        }
        #[cfg(not(feature = "s4u"))]
        Ok(None)
    }

    /// Return the lifetime of this credential
    pub fn lifetime(&self) -> Result<Duration, Error> {
        unsafe {
            let c = self.info_c(CredInfoC {
                lifetime: Some(0),
                ..CredInfoC::empty()
            })?;
            Ok(Duration::from_secs(c.lifetime.unwrap() as u64))
        }
    }

    /// Return the allowed usage of this credential
    pub fn usage(&self) -> Result<CredUsage, Error> {
        unsafe {
            let c = self.info_c(CredInfoC {
                usage: Some(0),
                ..CredInfoC::empty()
            })?;
            Ok(CredUsage::from_c(c.usage.unwrap())?)
        }
    }

    /// Return the mechanisms this credential may be used with
    pub fn mechanisms(&self) -> Result<OidSet, Error> {
        unsafe {
            let c = self.info_c(CredInfoC {
                mechanisms: Some(ptr::null_mut()),
                ..CredInfoC::empty()
            })?;
            Ok(OidSet::from_c(c.mechanisms.unwrap()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acquire() {
        Cred::acquire(None, None, CredUsage::Both, None)
            .expect("Failed to acquire credential");
    }

    #[test]
    fn test_gss_store() {
        let c = unsafe { Cred::from_c(NO_CRED) };
        c.gss_store(true, true, CredUsage::Both, None)
            .expect_err("Expected error when storing empty credential");
    }
}