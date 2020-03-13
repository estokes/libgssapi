use libgssapi_sys::*;
use std::{
    self, boxed::Box, clone::Clone, error, fmt, ops::{Deref, Drop}, ptr, result::Result, slice,
    sync::Arc,
};
use parking_lot::Mutex;

#[derive(Clone, Copy, Debug)]
pub struct Error {
    pub major: u32,
    pub minor: u32,
}

impl Error {
    fn fmt_code(f: &mut fmt::Formatter<'_>, code: u32) -> fmt::Result {
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
                    code,
                    GSS_C_GSS_CODE as i32,
                    ptr::null_mut::<gss_OID_desc>(),
                    &mut message_context as *mut OM_uint32,
                    &mut buf as gss_buffer_t,
                )
            };
            if major == GSS_S_COMPLETE {
                let s = unsafe {
                    slice::from_raw_parts(buf.value.cast::<u8>(), buf.length as usize)
                };
                let s = String::from_utf8_lossy(s);
                let res = write!(f, "gssapi error {}\n", s);
                let major = unsafe {
                    gss_release_buffer(
                        &mut minor as *mut OM_uint32,
                        &mut buf as gss_buffer_t,
                    )
                };
                if major != GSS_S_COMPLETE {
                    panic!("gss_release_buffer {}, {}\n", major, minor);
                }
                res?
            } else {
                write!(f, "gssapi unknown error code {}\n", code)?;
                break;
            }
            if message_context == 0 {
                break;
            }
        }
        Ok(())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Error::fmt_code(f, self.major)?;
        Ok(Error::fmt_code(f, self.minor)?)
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
            value: (*buf).as_mut_ptr().cast(),
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
                **self,
                &mut buf as gss_buffer_t,
                &mut oid as *mut gss_OID,
            )
        };
        if major == GSS_S_COMPLETE {
            let res = unsafe {
                slice::from_raw_parts(buf.value.cast::<u8>(), buf.length as usize)
            };
            let res = String::from_utf8_lossy(res).into_owned();
            let major = unsafe {
                gss_release_buffer(&mut minor as *mut OM_uint32, &mut buf as gss_buffer_t)
            };
            if major == GSS_S_COMPLETE {
                Ok(res)
            } else {
                Err(Error { major, minor })
            }
        } else {
            Err(Error { major, minor })
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CredUsage {
    Accept,
    Initiate,
    Both,
}

struct CredInner(gss_cred_id_t);

impl Drop for CredInner {
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

pub struct Cred(Arc<CredInner>);

impl Deref for Cred {
    type Target = gss_cred_id_t;

    fn deref(&self) -> &Self::Target {
        &(self.0).0
    }
}

impl Cred {
    pub fn acquire(
        name: Option<&Name>,
        time_req: Option<u32>,
        usage: CredUsage,
    ) -> Result<Cred, Error> {
        let name = name
            .map(|n| **n)
            .unwrap_or(ptr::null_mut::<gss_name_struct>());
        let time_req = time_req.unwrap_or(_GSS_C_INDEFINITE);
        let mut desired_mechs = {
            let mut s = OidSet::new()?;
            unsafe { s.add(gss_mech_krb5)? };
            s
        };
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
                name,
                time_req,
                desired_mechs.as_ptr(),
                usage as gss_cred_usage_t,
                &mut cred as *mut gss_cred_id_t,
                ptr::null_mut::<gss_OID_set>(),
                ptr::null_mut::<OM_uint32>(),
            )
        };
        if major == GSS_S_COMPLETE {
            Ok(Cred(Arc::new(CredInner(cred))))
        } else {
            Err(Error { major, minor })
        }
    }
}

/*
fn delete_ctx(mut ctx: gss_ctx_id_t) {
    let mut minor = GSS_S_COMPLETE;
    let _major = unsafe {
        gss_delete_sec_context(
            &mut minor as *mut OM_uint32,
            &mut ctx as *mut gss_ctx_id_t,
            ptr::null_mut::<gss_buffer_desc>(),
        )
    };
}

enum AcceptCtxInner {
    Uninit(Cred),
    Partial {
        ctx: gss_ctx_id_t,
        cred: Cred,
    },
    Complete {
        ctx: gss_ctx_id_t,
        delegated_cred: Cred
    }
}

impl Drop for AcceptCtxInner {
    fn drop(&mut self) {
        match self {
            AcceptCtxInner::Uninit(_) => (),
            AcceptCtxInner::Partial { ctx, .. } => delete_ctx(ctx),
            AcceptCtxInner::Complete { ctx, .. } => delete_ctx(ctx),
        }
    }
}

#[derive(Clone)]
pub struct AcceptCtx(Arc<Mutex<AcceptCtxInner>>);

impl Deref for AcceptCtx {
    type Target = Mutex<AcceptCtxInner>;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl AcceptCtx {
    fn new(cred: &Cred) -> AcceptCtx {
        AcceptCtx(Arc::new(Mutex::new(AcceptCtxInner(cred.clone()))))
    }

    fn step(&self, tok: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let mut inner = self.lock();
        let mut minor = GSS_S_COMPLETE;
        let mut (cred, ctx) = match inner {
            AcceptCtxInner::Uninit(cred) => {
                (cred.clone(), ptr::null_mut::<gss_ctx_id_struct>())
            }
            AcceptCtxInner::Partial { ctx, cred } => (cred.clone(), ctx),
            AcceptCtxInner::Complete {..} => return Ok(None),
        };
        let tok = GssBuf::from(tok);
        let mut out_tok = gss_buffer_desc_struct {
            length: 0,
            value: ptr::null_mut(),
        };
        let mut delegated_cred = ptr::null_mut::<gss_cred_id_struct>();
        let major = unsafe {
            gss_accept_sec_context(
                &mut minor as *mut OM_uint32,
                &mut ctx as *mut gss_ctx_id_t,
                **cred,
                tok.as_ptr(),
                ptr::null_mut::<gss_channel_bindings_struct>(),
                ptr::null_mut::<gss_name_t>(),
                ptr::null_mut::<gss_OID>(),
                &mut out_tok as gss_buffer_t,
                ptr::null_mut::<OM_uint32>(),
                ptr::null_mut::<OM_uint32>(),
                &mut delegated_cred as *mut gss_cred_id_t
            )
        };
    }
}

struct Context(gss_ctx_id_t);

impl Drop for Context {
    fn drop(&mut self) {
        delete_ctx(self.0)
    }
}
*/

fn run() -> Result<(), Error> {
    dbg!("start");
    let name = Name::new("nfs/ken-ohki.ryu-oh.org")?;
    dbg!("import name");
    let cname = name.canonicalize()?;
    dbg!("canonicalize name");
    let name_s = name.display()?;
    dbg!("display name");
    let cname_s = cname.display()?;
    dbg!("display cname");
    println!("name: {}, cname: {}", name_s, cname_s);
    let cred = Cred::acquire(Some(&cname), None, CredUsage::Accept)?;
    Ok(())
}

fn main() {
    match run() {
        Ok(()) => (),
        Err(e) => println!("{}", e),
    }
}
