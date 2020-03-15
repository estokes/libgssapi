#[macro_use]
extern crate bitflags;

use libgssapi_sys::*;
use parking_lot::Mutex;
use std::{
    clone::Clone,
    error, fmt,
    marker::PhantomData,
    mem,
    ops::{Deref, DerefMut, Drop},
    ptr,
    result::Result,
    slice,
    sync::Arc,
};

fn gss_error(x: OM_uint32) -> OM_uint32 {
    x & ((_GSS_C_CALLING_ERROR_MASK << GSS_C_CALLING_ERROR_OFFSET)
        | (_GSS_C_ROUTINE_ERROR_MASK << GSS_C_ROUTINE_ERROR_OFFSET))
}

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

#[repr(transparent)]
#[derive(Debug)]
struct BufRef<'a>(gss_buffer_desc_struct, PhantomData<&'a [u8]>);

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
    fn as_mut_ptr(&mut self) -> gss_buffer_t {
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
    fn empty() -> Buf {
        Buf(gss_buffer_desc {
            length: 0 as size_t,
            value: ptr::null_mut(),
        })
    }

    fn as_mut_ptr(&mut self) -> gss_buffer_t {
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

#[derive(Clone)]
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

bitflags! {
    pub struct CtxFlags: u32 {
        const GSS_C_DELEG_FLAG = GSS_C_DELEG_FLAG;
        const GSS_C_MUTUAL_FLAG = GSS_C_MUTUAL_FLAG;
        const GSS_C_REPLAY_FLAG = GSS_C_REPLAY_FLAG;
        const GSS_C_SEQUENCE_FLAG = GSS_C_SEQUENCE_FLAG;
        const GSS_C_CONF_FLAG = GSS_C_CONF_FLAG;
        const GSS_C_INTEG_FLAG = GSS_C_INTEG_FLAG;
        const GSS_C_ANON_FLAG = GSS_C_ANON_FLAG;
        const GSS_C_PROT_READY_FLAG = GSS_C_PROT_READY_FLAG;
        const GSS_C_TRANS_FLAG = GSS_C_TRANS_FLAG;
        const GSS_C_DELEG_POLICY_FLAG = GSS_C_DELEG_POLICY_FLAG;
    }
}

fn delete_ctx(mut ctx: gss_ctx_id_t) {
    if !ctx.is_null() {
        let mut minor = GSS_S_COMPLETE;
        let _major = unsafe {
            gss_delete_sec_context(
                &mut minor as *mut OM_uint32,
                &mut ctx as *mut gss_ctx_id_t,
                ptr::null_mut::<gss_buffer_desc>(),
            )
        };
    }
}

enum ServerCtxInner {
    Failed(Error),
    Uninit(Cred),
    Partial {
        ctx: gss_ctx_id_t,
        cred: Cred,
        delegated_cred: Option<Cred>,
        flags: CtxFlags,
    },
    Complete {
        ctx: gss_ctx_id_t,
        delegated_cred: Option<Cred>,
        flags: CtxFlags,
    },
}

impl Drop for ServerCtxInner {
    fn drop(&mut self) {
        match self {
            ServerCtxInner::Failed(_) | ServerCtxInner::Uninit(_) => (),
            ServerCtxInner::Partial { ctx, .. } => delete_ctx(*ctx),
            ServerCtxInner::Complete { ctx, .. } => delete_ctx(*ctx),
        }
    }
}

#[derive(Clone)]
pub struct ServerCtx(Arc<Mutex<ServerCtxInner>>);

impl ServerCtx {
    pub fn new(cred: &Cred) -> ServerCtx {
        ServerCtx(Arc::new(Mutex::new(ServerCtxInner::Uninit(cred.clone()))))
    }

    pub fn step(&self, tok: &[u8]) -> Result<Option<Buf>, Error> {
        let mut inner = self.0.lock();
        let mut minor = GSS_S_COMPLETE;
        let (cred, mut ctx, current_delegated_cred, mut flags) = match *inner {
            ServerCtxInner::Uninit(ref cred) => (
                cred.clone(),
                ptr::null_mut::<gss_ctx_id_struct>(),
                None,
                CtxFlags::empty(),
            ),
            ServerCtxInner::Partial {
                ctx,
                ref cred,
                ref delegated_cred,
                flags,
            } => (cred.clone(), ctx, delegated_cred.clone(), flags),
            ServerCtxInner::Complete { .. } => return Ok(None),
            ServerCtxInner::Failed(e) => return Err(e),
        };
        let mut tok = BufRef::from(tok);
        let mut out_tok = Buf::empty();
        let mut delegated_cred = ptr::null_mut::<gss_cred_id_struct>();
        let mut flag_bits: u32 = 0;
        let major = unsafe {
            gss_accept_sec_context(
                &mut minor as *mut OM_uint32,
                &mut ctx as *mut gss_ctx_id_t,
                *cred,
                tok.as_mut_ptr(),
                ptr::null_mut::<gss_channel_bindings_struct>(),
                ptr::null_mut::<gss_name_t>(),
                ptr::null_mut::<gss_OID>(),
                out_tok.as_mut_ptr(),
                &mut flag_bits as *mut OM_uint32,
                ptr::null_mut::<OM_uint32>(),
                &mut delegated_cred as *mut gss_cred_id_t,
            )
        };
        let delegated_cred = {
            if delegated_cred.is_null() {
                None
            } else {
                match current_delegated_cred {
                    None => Some(Cred(Arc::new(CredInner(delegated_cred)))),
                    Some(current) => {
                        if *current == delegated_cred {
                            Some(current)
                        } else {
                            Some(Cred(Arc::new(CredInner(delegated_cred))))
                        }
                    }
                }
            }
        };
        if let Some(new_flags) = CtxFlags::from_bits(flag_bits) {
            flags.insert(new_flags);
        }
        if gss_error(major) > 0 {
            let e = Error { major, minor };
            *inner = ServerCtxInner::Failed(e);
            delete_ctx(ctx);
            Err(e)
        } else if major & _GSS_S_CONTINUE_NEEDED > 0 {
            *inner = ServerCtxInner::Partial {
                ctx,
                cred,
                delegated_cred,
                flags,
            };
            Ok(Some(out_tok))
        } else {
            *inner = ServerCtxInner::Complete {
                ctx,
                delegated_cred,
                flags,
            };
            if out_tok.len() > 0 {
                Ok(Some(out_tok))
            } else {
                Ok(None)
            }
        }
    }
}

enum ClientCtxInner {
    Failed(Error),
    Uninit {
        cred: Cred,
        target: Name,
        flags: CtxFlags,
    },
    Partial {
        ctx: gss_ctx_id_t,
        cred: Cred,
        target: Name,
        flags: CtxFlags,
    },
    Complete(gss_ctx_id_t),
}

impl Drop for ClientCtxInner {
    fn drop(&mut self) {
        match self {
            ClientCtxInner::Failed(_) | ClientCtxInner::Uninit { .. } => (),
            ClientCtxInner::Partial { ctx, .. } => delete_ctx(*ctx),
            ClientCtxInner::Complete(ctx) => delete_ctx(*ctx),
        }
    }
}

#[derive(Clone)]
pub struct ClientCtx(Arc<Mutex<ClientCtxInner>>);

impl ClientCtx {
    pub fn new(cred: &Cred, target: &Name, flags: CtxFlags) -> ClientCtx {
        let inner = ClientCtxInner::Uninit {
            cred: cred.clone(),
            target: target.clone(),
            flags,
        };
        ClientCtx(Arc::new(Mutex::new(inner)))
    }

    pub fn step(&self, tok: Option<&[u8]>) -> Result<Option<Buf>, Error> {
        let mut inner = self.0.lock();
        let mut minor = GSS_S_COMPLETE;
        let mut tok = tok.map(BufRef::from);
        let mut out_tok = Buf::empty();
        let (mut ctx, cred, target, flags) = match *inner {
            ClientCtxInner::Uninit {
                ref cred,
                ref target,
                flags,
            } => (
                ptr::null_mut::<gss_ctx_id_struct>(),
                cred.clone(),
                target.clone(),
                flags,
            ),
            ClientCtxInner::Partial {
                ctx,
                ref cred,
                ref target,
                flags,
            } => (ctx, cred.clone(), target.clone(), flags),
            ClientCtxInner::Failed(e) => return Err(e),
            ClientCtxInner::Complete(_) => return Ok(None),
        };
        let major = unsafe {
            gss_init_sec_context(
                &mut minor as *mut OM_uint32,
                *cred,
                &mut ctx as *mut gss_ctx_id_t,
                *target,
                gss_mech_krb5,
                flags.bits(),
                _GSS_C_INDEFINITE,
                ptr::null_mut::<gss_channel_bindings_struct>(),
                match tok {
                    None => ptr::null_mut::<gss_buffer_desc>(),
                    Some(ref mut tok) => tok.as_mut_ptr()
                },
                ptr::null_mut::<gss_OID>(),
                out_tok.as_mut_ptr(),
                ptr::null_mut::<OM_uint32>(),
                ptr::null_mut::<OM_uint32>(),
            )
        };
        if gss_error(major) > 0 {
            let e = Error { major, minor };
            *inner = ClientCtxInner::Failed(e);
            delete_ctx(ctx);
            Err(e)
        } else if major & _GSS_S_CONTINUE_NEEDED > 0 {
            *inner = ClientCtxInner::Partial {
                ctx,
                cred,
                target,
                flags,
            };
            Ok(Some(out_tok))
        } else {
            *inner = ClientCtxInner::Complete(ctx);
            if out_tok.len() > 0 {
                Ok(Some(out_tok))
            } else {
                Ok(None)
            }
        }
    }
}
