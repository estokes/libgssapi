use libgssapi_sys::*;
use std::{
    self, slice, error, fmt, ptr,
    ops::Drop,
    clone::Clone,
    result::Result,
    boxed::Box,
};

#[derive(Clone, Copy, Debug)]
pub struct Error {
    pub major: u32,
    pub minor: u32,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut message_context: OM_uint32 = 0;
        loop {
            let mut minor = GSS_S_COMPLETE as OM_uint32;
            let mut buf = gss_buffer_desc_struct {
                length: 0,
                value: ptr::null_mut::<std::os::raw::c_void>(),
            };
            let major = unsafe {
                gss_display_status(
                    &mut minor as *mut OM_uint32,
                    self.major,
                    GSS_C_GSS_CODE as i32,
                    ptr::null_mut::<gss_OID_desc>(),
                    &mut message_context as *mut OM_uint32,
                    &mut buf as gss_buffer_t
                )
            };
            if major == GSS_S_COMPLETE {
                let s = unsafe {
                    slice::from_raw_parts(
                        buf.value.cast::<u8>(), buf.length as usize
                    )
                };
                let s = String::from_utf8_lossy(s);
                let res = write!(f, "gssapi error {}", s);
                let major = unsafe {
                    gss_release_buffer(
                        &mut minor as *mut OM_uint32,
                        &mut buf as gss_buffer_t
                    )
                };
                if major != GSS_S_COMPLETE {
                    panic!("gss_release_buffer {}, {}", major, minor);
                }
                res?
            } else {
                write!(
                    f, "gssapi unknown error major {} minor {}",
                    self.major, self.minor
                )?;
                break;
            }
            if message_context == 0 { break; }
        }
        Ok(())
    }
}

impl error::Error for Error {}

#[allow(dead_code)]
struct GssBuf {
    buf: Box<[u8]>,
    gss_buf: gss_buffer_desc_struct,
}

impl From<&[u8]> for GssBuf {
    fn from(s: &[u8]) -> Self {
        let mut buf: Box<[u8]> = Box::from(s);
        let gss_buf = gss_buffer_desc_struct {
            length: buf.len() as size_t,
            value: (*buf).as_mut_ptr().cast()
        };
        GssBuf { buf, gss_buf }
    }
}

impl GssBuf {
    fn as_ptr(&mut self) -> gss_buffer_t {
        &mut self.gss_buf as gss_buffer_t
    }
}

struct OidSet(gss_OID_set);

impl Drop for OidSet {
    fn drop(&mut self) {
        let mut _minor = GSS_S_COMPLETE;
        let _major = unsafe {
            gss_release_oid_set(
                &mut _minor as *mut OM_uint32,
                &mut self.0 as *mut gss_OID_set
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
                &mut out as *mut gss_OID_set
            )
        };
        if major == GSS_S_COMPLETE {
            Ok(OidSet(out))
        } else {
            Err(Error {major, minor})
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
                &mut self.0 as *mut gss_OID_set
            )
        };
        if major == GSS_S_COMPLETE {
            Ok(())
        } else {
            Err(Error {major, minor})
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
                &mut present as *mut std::os::raw::c_int
            )
        };
        if major == GSS_S_COMPLETE {
            Ok(if present != 0 { true } else { false })
        } else {
            Err(Error {major, minor})
        }
    }
}

pub struct Name(gss_name_t);

impl Drop for Name {
    fn drop(&mut self) {
        let mut _minor = GSS_S_COMPLETE;
        let major = unsafe {
            gss_release_name(
                &mut _minor as *mut OM_uint32,
                &mut self.0 as *mut gss_name_t
            )
        };
        if major != GSS_S_COMPLETE {
            // CR estokes: log this? panic?
            ()
        }
    }
}

impl Name {
    pub fn new(s: &str) -> Result<Self, Error> {
        let mut buf = GssBuf::from(s.as_bytes());
        let mut minor = GSS_S_COMPLETE;
        let mut name = ptr::null_mut::<gss_name_struct>();
        let major = unsafe {
            gss_import_name(
                &mut minor as *mut OM_uint32,
                buf.as_ptr(),
                ptr::null_mut::<gss_OID_desc>(),
                &mut name as *mut gss_name_t,
            )
        };
        if major == GSS_S_COMPLETE {
            Ok(Name(name))
        } else {
            Err(Error {major, minor})
        }
    }

    pub fn canonicalize(&self) -> Result<Self, Error> {
        let mut out = ptr::null_mut::<gss_name_struct>();
        let mut minor = GSS_S_COMPLETE;
        let major = unsafe {
            gss_canonicalize_name(
                &mut minor as *mut OM_uint32,
                self.0,
                gss_mech_krb5,
                &mut out as *mut gss_name_t
            )
        };
        if major == GSS_S_COMPLETE {
            Ok(Name(out))
        } else {
            Err(Error {major, minor})
        }
    }

    pub fn duplicate(&self) -> Result<Self, Error> {
        let mut copy = ptr::null_mut::<gss_name_struct>();
        let mut minor = GSS_S_COMPLETE;
        let major = unsafe {
            gss_duplicate_name(
                &mut minor as *mut OM_uint32,
                self.0,
                &mut copy as *mut gss_name_t
            )
        };
        if major == GSS_S_COMPLETE {
            Ok(Name(copy))
        } else {
            Err(Error {major, minor})
        }
    }

    pub fn display(&self) -> Result<String, Error> {
        let mut minor = GSS_S_COMPLETE;
        let mut buf = gss_buffer_desc_struct {
            length: 0,
            value: ptr::null_mut::<std::os::raw::c_void>(),
        };
        let mut oid = ptr::null_mut::<gss_OID_desc>();
        let major = unsafe {
            gss_display_name(
                &mut minor as *mut OM_uint32,
                self.0,
                &mut buf as gss_buffer_t,
                &mut oid as *mut gss_OID
            )
        };
        if major == GSS_S_COMPLETE {
            let res = unsafe {
                slice::from_raw_parts(buf.value.cast::<u8>(), buf.length as usize)
            };
            let res = String::from_utf8_lossy(res).into_owned();
            let major = unsafe {
                gss_release_buffer(
                    &mut minor as *mut OM_uint32,
                    &mut buf as gss_buffer_t
                )
            };
            if major == GSS_S_COMPLETE {
                Ok(res)
            } else {
                Err(Error {major, minor})
            }
        } else {
            Err(Error {major, minor})
        }
    }
}

/*
#[derive(Clone, Copy, Debug)]
pub enum CredUsage {
    Accept,
    Initiate,
    Both
}

pub struct Cred(gss_cred_id_t);

impl Drop for Cred {
    fn drop(&mut self) {
        let mut minor = GSS_S_COMPLETE;
        let _major = gss_release_cred(
            &mut minor as *mut OM_uint32,
            &mut self.0 as *mut gss_cred_id_t
        );
        // CR estokes: log errors? panic?
    }
}

impl Cred {
    pub fn acquire(
        name: Option<Name>,
        time_req: Option<u64>,
        usage: CredUsage
    ) -> Result<Cred, Error> {
        
    }
}
*/

fn run() -> Result<(), Error> {
    dbg!("start");
    let name = Name::new("nfs/ryouko")?;
    dbg!("import name");
    let cname = name.canonicalize()?;
    dbg!("canonicalize name");
    let name_s = name.display()?;
    dbg!("display name");
    let cname_s = cname.display()?;
    dbg!("display cname");
    println!("name: {}, cname: {}", name_s, cname_s);
    Ok(())
}

fn main() {
    match run() {
        Ok(()) => (),
        Err(e) => println!("{}", e),
    }
}
