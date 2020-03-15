

struct NameInner(gss_name_t);

impl Drop for NameInner {
    fn drop(&mut self) {
        let mut _minor = GSS_S_COMPLETE;
        let major = unsafe {
            gss_release_name(
                &mut _minor as *mut OM_uint32,
                &mut self.0 as *mut gss_name_t,
            )
        };
        if major != GSS_S_COMPLETE {
            // CR estokes: log this? panic?
            ()
        }
    }
}

#[derive(Clone)]
pub struct Name(Arc<NameInner>);

impl Deref for Name {
    type Target = gss_name_t;

    fn deref(&self) -> &Self::Target {
        &(self.0).0
    }
}

impl Name {
    pub fn new(s: &[u8]) -> Result<Self, Error> {
        let mut buf = BufRef::from(s);
        let mut minor = GSS_S_COMPLETE;
        let mut name = ptr::null_mut::<gss_name_struct>();
        let major = unsafe {
            gss_import_name(
                &mut minor as *mut OM_uint32,
                buf.as_mut_ptr(),
                ptr::null_mut::<gss_OID_desc>(),
                &mut name as *mut gss_name_t,
            )
        };
        if major == GSS_S_COMPLETE {
            Ok(Name(Arc::new(NameInner(name))))
        } else {
            Err(Error { major, minor })
        }
    }

    pub fn canonicalize(&self) -> Result<Self, Error> {
        let mut out = ptr::null_mut::<gss_name_struct>();
        let mut minor = GSS_S_COMPLETE;
        let major = unsafe {
            gss_canonicalize_name(
                &mut minor as *mut OM_uint32,
                **self,
                gss_mech_krb5,
                &mut out as *mut gss_name_t,
            )
        };
        if major == GSS_S_COMPLETE {
            Ok(Name(Arc::new(NameInner(out))))
        } else {
            Err(Error { major, minor })
        }
    }

    // CR estokes: is this even needed?
    pub fn duplicate(&self) -> Result<Self, Error> {
        let mut copy = ptr::null_mut::<gss_name_struct>();
        let mut minor = GSS_S_COMPLETE;
        let major = unsafe {
            gss_duplicate_name(
                &mut minor as *mut OM_uint32,
                **self,
                &mut copy as *mut gss_name_t,
            )
        };
        if major == GSS_S_COMPLETE {
            Ok(Name(Arc::new(NameInner(copy))))
        } else {
            Err(Error { major, minor })
        }
    }

    pub fn display(&self) -> Result<Buf, Error> {
        let mut minor = GSS_S_COMPLETE;
        let mut buf = Buf::empty();
        let mut oid = ptr::null_mut::<gss_OID_desc>();
        let major = unsafe {
            gss_display_name(
                &mut minor as *mut OM_uint32,
                **self,
                buf.as_mut_ptr(),
                &mut oid as *mut gss_OID,
            )
        };
        if major == GSS_S_COMPLETE {
            Ok(buf)
        } else {
            Err(Error { major, minor })
        }
    }
}
