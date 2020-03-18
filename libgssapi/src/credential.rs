use crate::{error::Error, name::Name, oid::{OidSet, NO_OID_SET}};
use libgssapi_sys::{
    gss_OID_set, gss_acquire_cred, gss_cred_id_struct, gss_cred_id_t, gss_cred_usage_t,
    gss_name_struct, gss_release_cred, OM_uint32, GSS_C_ACCEPT,
    GSS_C_BOTH, GSS_C_INITIATE, GSS_S_COMPLETE, _GSS_C_INDEFINITE,
};
use std::{ptr, fmt};

#[derive(Clone, Copy, Debug)]
pub enum CredUsage {
    Accept,
    Initiate,
    Both,
}

/// gssapi credentials.
pub struct Cred(gss_cred_id_t);

impl Drop for Cred {
    fn drop(&mut self) {
        let mut minor = GSS_S_COMPLETE;
        let _major = unsafe {
            gss_release_cred(
                &mut minor as *mut OM_uint32,
                &mut self.0 as *mut gss_cred_id_t,
            )
        };
        // CR estokes: log errors? panic?
    }
}

unsafe impl Send for Cred {}
unsafe impl Sync for Cred {}

impl fmt::Debug for Cred {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "<gss credential>")
    }
}

impl Cred {
    /// Acquire gssapi credentials for `name` or the default name,
    /// lasting for `time_req` or as long as possible, for the purpose
    /// of `usage`, and for use with `desired_mechs` or the default
    /// mechanism.
    pub fn acquire(
        name: Option<&Name>,
        time_req: Option<u32>,
        usage: CredUsage,
        desired_mechs: Option<&OidSet>,
    ) -> Result<Cred, Error> {
        let time_req = time_req.unwrap_or(_GSS_C_INDEFINITE);
        let usage = match usage {
            CredUsage::Both => GSS_C_BOTH,
            CredUsage::Initiate => GSS_C_INITIATE,
            CredUsage::Accept => GSS_C_ACCEPT,
        };
        let mut minor = GSS_S_COMPLETE;
        let mut cred = ptr::null_mut::<gss_cred_id_struct>();
        let major = unsafe {
            gss_acquire_cred(
                &mut minor as *mut OM_uint32,
                match name {
                    None => ptr::null_mut::<gss_name_struct>(),
                    Some(n) => n.to_c()
                },
                time_req,
                match desired_mechs {
                    None => NO_OID_SET,
                    Some(desired_mechs) => desired_mechs.to_c()
                },
                usage as gss_cred_usage_t,
                &mut cred as *mut gss_cred_id_t,
                ptr::null_mut::<gss_OID_set>(),
                ptr::null_mut::<OM_uint32>(),
            )
        };
        if major == GSS_S_COMPLETE {
            Ok(Cred(cred))
        } else {
            Err(Error { major, minor })
        }
    }

    pub(crate) unsafe fn from_c(cred: gss_cred_id_t) -> Cred {
        Cred(cred)
    }

    pub(crate) unsafe fn to_c(&self) -> gss_cred_id_t {
        self.0
    }
}
