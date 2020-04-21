use crate::{
    credential::Cred,
    error::{gss_error, Error, MajorFlags},
    name::Name,
    oid::{Oid, NO_OID},
    util::{Buf, BufRef, GssIov, GssIovFake, GssIovReal},
};
use libgssapi_sys::{
    gss_OID, gss_accept_sec_context, gss_buffer_desc, gss_channel_bindings_struct,
    gss_cred_id_struct, gss_cred_id_t, gss_ctx_id_t, gss_delete_sec_context,
    gss_init_sec_context, gss_inquire_context, gss_name_t, gss_unwrap, gss_wrap,
    OM_uint32, GSS_C_ANON_FLAG, GSS_C_CONF_FLAG, GSS_C_DELEG_FLAG,
    GSS_C_DELEG_POLICY_FLAG, GSS_C_INTEG_FLAG, GSS_C_MUTUAL_FLAG, GSS_C_PROT_READY_FLAG,
    GSS_C_QOP_DEFAULT, GSS_C_REPLAY_FLAG, GSS_C_SEQUENCE_FLAG, GSS_C_TRANS_FLAG,
    GSS_S_COMPLETE, _GSS_C_INDEFINITE, _GSS_S_CONTINUE_NEEDED,
};
use parking_lot::Mutex;
use std::{ptr, sync::Arc, time::Duration};

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

unsafe fn wrap(ctx: gss_ctx_id_t, encrypt: bool, msg: &[u8]) -> Result<Buf, Error> {
    let mut minor = GSS_S_COMPLETE;
    let mut msg = BufRef::from(msg);
    let mut enc_msg = Buf::empty();
    let major = gss_wrap(
        &mut minor as *mut OM_uint32,
        ctx,
        if encrypt { 1 } else { 0 },
        GSS_C_QOP_DEFAULT,
        msg.to_c(),
        ptr::null_mut(),
        enc_msg.to_c(),
    );
    if major == GSS_S_COMPLETE {
        Ok(enc_msg)
    } else {
        Err(Error {
            major: MajorFlags::from_bits_unchecked(major),
            minor,
        })
    }
}

unsafe fn wrap_iov(
    ctx: gss_ctx_id_t,
    encrypt: bool,
    msg: &mut [GssIov<GssIovReal>],
) -> Result<(), Error> {
    let mut minor = GSS_S_COMPLETE;
    let major = gss_wrap_iov(
        &mut minor as *mut OM_uint32,
        ctx,
        if encrypt { 1 } else { 0 },
        GSS_C_QOP_DEFAULT,
        ptr::null_mut(),
        mem::transmute::<*mut GssIov<GssIovReal>, *mut gss_iov_buffer_desc>(
            msg.as_mut_ptr()
        ),
        msg.len() as size_t
    );
    if major == GSS_S_COMPLETE {
        Ok(())
    } else {
        Err(Error {
            major: MajorFlags::from_bits_unchecked(major),
            minor
        })
    }
}

unsafe fn unwrap(ctx: gss_ctx_id_t, msg: &[u8]) -> Result<Buf, Error> {
    let mut minor = GSS_S_COMPLETE;
    let mut msg = BufRef::from(msg);
    let mut out = Buf::empty();
    let major = gss_unwrap(
        &mut minor as *mut OM_uint32,
        ctx,
        msg.to_c(),
        out.to_c(),
        ptr::null_mut::<i32>(),
        ptr::null_mut::<OM_uint32>(),
    );
    if major == GSS_S_COMPLETE {
        Ok(out)
    } else {
        Err(Error {
            major: MajorFlags::from_bits_unchecked(major),
            minor,
        })
    }
}

#[derive(Debug)]
pub struct CtxInfo {
    pub source_name: Name,
    pub target_name: Name,
    pub lifetime: Duration,
    pub mechanism: &'static Oid,
    pub flags: CtxFlags,
    pub local: bool,
    pub open: bool,
}

struct CtxInfoC {
    source_name: Option<gss_name_t>,
    target_name: Option<gss_name_t>,
    lifetime: Option<u32>,
    mechanism: Option<gss_OID>,
    flags: Option<u32>,
    local: Option<i32>,
    open: Option<i32>,
}

impl CtxInfoC {
    fn empty() -> Self {
        CtxInfoC {
            source_name: None,
            target_name: None,
            lifetime: None,
            mechanism: None,
            flags: None,
            local: None,
            open: None,
        }
    }
}

unsafe fn info(ctx: gss_ctx_id_t, mut ifo: CtxInfoC) -> Result<CtxInfoC, Error> {
    let mut minor: u32 = 0;
    let major = gss_inquire_context(
        &mut minor as *mut u32,
        ctx,
        match ifo.source_name {
            None => ptr::null_mut::<gss_name_t>(),
            Some(ref mut n) => n as *mut gss_name_t,
        },
        match ifo.target_name {
            None => ptr::null_mut::<gss_name_t>(),
            Some(ref mut n) => n as *mut gss_name_t,
        },
        match ifo.lifetime {
            None => ptr::null_mut::<u32>(),
            Some(ref mut l) => l as *mut u32,
        },
        match ifo.mechanism {
            None => ptr::null_mut::<gss_OID>(),
            Some(ref mut o) => o as *mut gss_OID,
        },
        match ifo.flags {
            None => ptr::null_mut::<u32>(),
            Some(ref mut f) => f as *mut u32,
        },
        match ifo.local {
            None => ptr::null_mut::<i32>(),
            Some(ref mut l) => l as *mut i32,
        },
        match ifo.open {
            None => ptr::null_mut::<i32>(),
            Some(ref mut o) => o as *mut i32,
        },
    );
    if gss_error(major) > 0 {
        // make sure we free anything that was successfully allocated
        if let Some(source_name) = ifo.source_name {
            Name::from_c(source_name);
        }
        if let Some(target_name) = ifo.target_name {
            Name::from_c(target_name);
        }
        Err(Error {
            major: MajorFlags::from_bits_unchecked(major),
            minor,
        })
    } else {
        Ok(ifo)
    }
}

unsafe fn full_info(ctx: gss_ctx_id_t) -> Result<CtxInfo, Error> {
    let c = info(
        ctx,
        CtxInfoC {
            source_name: Some(ptr::null_mut()),
            target_name: Some(ptr::null_mut()),
            lifetime: Some(0),
            mechanism: Some(ptr::null_mut()),
            flags: Some(0),
            local: Some(0),
            open: Some(0),
        },
    )?;
    Ok(CtxInfo {
        source_name: Name::from_c(c.source_name.unwrap()),
        target_name: Name::from_c(c.target_name.unwrap()),
        lifetime: Duration::from_secs(c.lifetime.unwrap() as u64),
        mechanism: Oid::from_c(c.mechanism.unwrap()),
        flags: CtxFlags::from_bits_unchecked(c.flags.unwrap()),
        local: c.local.unwrap() > 0,
        open: c.open.unwrap() > 0,
    })
}

unsafe fn source_name(ctx: gss_ctx_id_t) -> Result<Name, Error> {
    let c = info(
        ctx,
        CtxInfoC {
            source_name: Some(ptr::null_mut()),
            ..CtxInfoC::empty()
        },
    )?;
    Ok(Name::from_c(c.source_name.unwrap()))
}

unsafe fn target_name(ctx: gss_ctx_id_t) -> Result<Name, Error> {
    let c = info(
        ctx,
        CtxInfoC {
            target_name: Some(ptr::null_mut()),
            ..CtxInfoC::empty()
        },
    )?;
    Ok(Name::from_c(c.target_name.unwrap()))
}

unsafe fn lifetime(ctx: gss_ctx_id_t) -> Result<Duration, Error> {
    let c = info(
        ctx,
        CtxInfoC {
            lifetime: Some(0),
            ..CtxInfoC::empty()
        },
    )?;
    Ok(Duration::from_secs(c.lifetime.unwrap() as u64))
}

unsafe fn mechanism(ctx: gss_ctx_id_t) -> Result<&'static Oid, Error> {
    let c = info(
        ctx,
        CtxInfoC {
            mechanism: Some(ptr::null_mut()),
            ..CtxInfoC::empty()
        },
    )?;
    Ok(Oid::from_c(c.mechanism.unwrap()))
}

unsafe fn flags(ctx: gss_ctx_id_t) -> Result<CtxFlags, Error> {
    let c = info(
        ctx,
        CtxInfoC {
            flags: Some(0),
            ..CtxInfoC::empty()
        },
    )?;
    Ok(CtxFlags::from_bits_unchecked(c.flags.unwrap()))
}

unsafe fn local(ctx: gss_ctx_id_t) -> Result<bool, Error> {
    let c = info(
        ctx,
        CtxInfoC {
            local: Some(0),
            ..CtxInfoC::empty()
        },
    )?;
    Ok(c.local.unwrap() > 0)
}

unsafe fn open(ctx: gss_ctx_id_t) -> Result<bool, Error> {
    let c = info(
        ctx,
        CtxInfoC {
            open: Some(0),
            ..CtxInfoC::empty()
        },
    )?;
    Ok(c.open.unwrap() > 0)
}

pub trait SecurityContext {
    /// Wrap a message with optional encryption. If `encrypt` is true
    /// then only the other side of the context can read the
    /// message. In any case the other side can always verify message
    /// integrity.
    fn wrap(&self, encrypt: bool, msg: &[u8]) -> Result<Buf, Error>;

    /// Unwrap a wrapped message, checking it's integrity and
    /// decrypting it if necessary.
    fn unwrap(&self, msg: &[u8]) -> Result<Buf, Error>;

    /// Get all information about a security context in one call
    fn info(&self) -> Result<CtxInfo, Error>;

    /// Get the source name of the security context
    fn source_name(&self) -> Result<Name, Error>;

    /// Get the target name of the security context
    fn target_name(&self) -> Result<Name, Error>;

    /// Get the lifetime of the security context
    fn lifetime(&self) -> Result<Duration, Error>;

    /// Get the mechanism of the security context
    fn mechanism(&self) -> Result<&'static Oid, Error>;

    /// Get the flags of the security context
    fn flags(&self) -> Result<CtxFlags, Error>;

    /// Return true if the security context was locally initiated
    fn local(&self) -> Result<bool, Error>;

    /// Return true if the security context is open
    fn open(&self) -> Result<bool, Error>;
}

#[derive(Debug)]
enum ServerCtxState {
    Uninitialized,
    Failed(Error),
    Partial,
    Complete,
}

#[derive(Debug)]
struct ServerCtxInner {
    ctx: gss_ctx_id_t,
    cred: Cred,
    delegated_cred: Option<Cred>,
    flags: CtxFlags,
    state: ServerCtxState,
}

impl Drop for ServerCtxInner {
    fn drop(&mut self) {
        delete_ctx(self.ctx);
    }
}

unsafe impl Send for ServerCtxInner {}
unsafe impl Sync for ServerCtxInner {}

/// The server side of a security context. Contexts are wrapped in and
/// Arc<Mutex<_>> internally, so clones work and you can use them
/// safely from other threads.
#[derive(Debug, Clone)]
pub struct ServerCtx(Arc<Mutex<ServerCtxInner>>);

impl ServerCtx {
    /// Create a new uninitialized server context with the specified
    /// credentials. You must then call `step` until the context is
    /// fully initialized. The mechanism is not specified because it
    /// is dictated by the client.
    pub fn new(cred: Cred) -> ServerCtx {
        ServerCtx(Arc::new(Mutex::new(ServerCtxInner {
            ctx: ptr::null_mut(),
            cred: cred,
            delegated_cred: None,
            flags: CtxFlags::empty(),
            state: ServerCtxState::Uninitialized,
        })))
    }

    /// Perform 1 step in the initialization of the server context,
    /// feeding it a token you received from the client. If
    /// initialization is complete from the point of view of the
    /// server then this will return Ok(None). Otherwise it will
    /// return a token that needs to be sent to the client and fed to
    /// `ClientCtx::step`.
    pub fn step(&self, tok: &[u8]) -> Result<Option<Buf>, Error> {
        let mut inner = self.0.lock();
        match inner.state {
            ServerCtxState::Uninitialized | ServerCtxState::Partial => (),
            ServerCtxState::Failed(e) => return Err(e),
            ServerCtxState::Complete => return Ok(None),
        }
        let mut minor = GSS_S_COMPLETE;
        let mut tok = BufRef::from(tok);
        let mut out_tok = Buf::empty();
        let mut delegated_cred = ptr::null_mut::<gss_cred_id_struct>();
        let mut flag_bits: u32 = 0;
        let major = unsafe {
            gss_accept_sec_context(
                &mut minor as *mut OM_uint32,
                &mut inner.ctx as *mut gss_ctx_id_t,
                inner.cred.to_c(),
                tok.to_c(),
                ptr::null_mut::<gss_channel_bindings_struct>(),
                ptr::null_mut::<gss_name_t>(),
                ptr::null_mut::<gss_OID>(),
                out_tok.to_c(),
                &mut flag_bits as *mut OM_uint32,
                ptr::null_mut::<OM_uint32>(),
                &mut delegated_cred as *mut gss_cred_id_t,
            )
        };
        if !delegated_cred.is_null() {
            match &inner.delegated_cred {
                None => unsafe {
                    inner.delegated_cred = Some(Cred::from_c(delegated_cred));
                },
                Some(current) => unsafe {
                    if current.to_c() != delegated_cred {
                        inner.delegated_cred = Some(Cred::from_c(delegated_cred));
                    }
                },
            }
        }
        if let Some(new_flags) = CtxFlags::from_bits(flag_bits) {
            inner.flags.insert(new_flags);
        }
        if gss_error(major) > 0 {
            let e = Error {
                major: unsafe { MajorFlags::from_bits_unchecked(major) },
                minor,
            };
            inner.state = ServerCtxState::Failed(e);
            Err(e)
        } else if major & _GSS_S_CONTINUE_NEEDED > 0 {
            inner.state = ServerCtxState::Partial;
            Ok(Some(out_tok))
        } else {
            inner.state = ServerCtxState::Complete;
            if out_tok.len() > 0 {
                Ok(Some(out_tok))
            } else {
                Ok(None)
            }
        }
    }
}

impl SecurityContext for ServerCtx {
    fn wrap(&self, encrypt: bool, msg: &[u8]) -> Result<Buf, Error> {
        let inner = self.0.lock();
        unsafe { wrap(inner.ctx, encrypt, msg) }
    }

    fn unwrap(&self, msg: &[u8]) -> Result<Buf, Error> {
        let inner = self.0.lock();
        unsafe { unwrap(inner.ctx, msg) }
    }

    fn info(&self) -> Result<CtxInfo, Error> {
        let inner = self.0.lock();
        unsafe { full_info(inner.ctx) }
    }

    fn source_name(&self) -> Result<Name, Error> {
        let inner = self.0.lock();
        unsafe { source_name(inner.ctx) }
    }

    fn target_name(&self) -> Result<Name, Error> {
        let inner = self.0.lock();
        unsafe { target_name(inner.ctx) }
    }

    fn lifetime(&self) -> Result<Duration, Error> {
        let inner = self.0.lock();
        unsafe { lifetime(inner.ctx) }
    }

    fn mechanism(&self) -> Result<&'static Oid, Error> {
        let inner = self.0.lock();
        unsafe { mechanism(inner.ctx) }
    }

    fn flags(&self) -> Result<CtxFlags, Error> {
        let inner = self.0.lock();
        unsafe { flags(inner.ctx) }
    }

    fn local(&self) -> Result<bool, Error> {
        let inner = self.0.lock();
        unsafe { local(inner.ctx) }
    }

    fn open(&self) -> Result<bool, Error> {
        let inner = self.0.lock();
        unsafe { open(inner.ctx) }
    }
}

#[derive(Debug)]
enum ClientCtxState {
    Uninitialized,
    Failed(Error),
    Partial,
    Complete,
}

#[derive(Debug)]
struct ClientCtxInner {
    ctx: gss_ctx_id_t,
    cred: Cred,
    target: Name,
    flags: CtxFlags,
    state: ClientCtxState,
    mech: Option<&'static Oid>,
}

impl Drop for ClientCtxInner {
    fn drop(&mut self) {
        delete_ctx(self.ctx);
    }
}

unsafe impl Send for ClientCtxInner {}
unsafe impl Sync for ClientCtxInner {}

/// The client side of a security context. Contexts are wrapped in and
/// Arc<Mutex<_>> internally, so clones work and you can use them
/// safely from other threads.
#[derive(Debug, Clone)]
pub struct ClientCtx(Arc<Mutex<ClientCtxInner>>);

impl ClientCtx {
    /// Create a new uninitialized client security context using the
    /// specified credentials, targeting the service named by target,
    /// and optionally using a specific mechanism (otherwise gssapi
    /// will pick a default for you). To finish initializing the
    /// context you must call `step`.
    pub fn new(
        cred: Cred,
        target: Name,
        flags: CtxFlags,
        mech: Option<&'static Oid>,
    ) -> ClientCtx {
        let inner = ClientCtxInner {
            ctx: ptr::null_mut(),
            cred: cred,
            target: target,
            flags,
            state: ClientCtxState::Uninitialized,
            mech,
        };
        ClientCtx(Arc::new(Mutex::new(inner)))
    }

    /// Perform 1 step in the initialization of the specfied security
    /// context. Since the client initiates context creation, the
    /// token will initially be None, and gssapi will give you a token
    /// to send to the server. The server may send back a token, which
    /// you must feed to this function, and possibly get another token
    /// to send to the server. This will go on a mechanism specifiec
    /// number of times until step returns `Ok(None)`. At that point
    /// the context is fully initialized.
    pub fn step(&self, tok: Option<&[u8]>) -> Result<Option<Buf>, Error> {
        let mut inner = self.0.lock();
        match inner.state {
            ClientCtxState::Uninitialized | ClientCtxState::Partial => (),
            ClientCtxState::Failed(e) => return Err(e),
            ClientCtxState::Complete => return Ok(None),
        };
        let mut minor = GSS_S_COMPLETE;
        let mut tok = tok.map(BufRef::from);
        let mut out_tok = Buf::empty();
        let major = unsafe {
            gss_init_sec_context(
                &mut minor as *mut OM_uint32,
                inner.cred.to_c(),
                &mut inner.ctx as *mut gss_ctx_id_t,
                inner.target.to_c(),
                match inner.mech {
                    None => NO_OID,
                    Some(mech) => mech.to_c(),
                },
                inner.flags.bits(),
                _GSS_C_INDEFINITE,
                ptr::null_mut::<gss_channel_bindings_struct>(),
                match tok {
                    None => ptr::null_mut::<gss_buffer_desc>(),
                    Some(ref mut tok) => tok.to_c(),
                },
                ptr::null_mut::<gss_OID>(),
                out_tok.to_c(),
                ptr::null_mut::<OM_uint32>(),
                ptr::null_mut::<OM_uint32>(),
            )
        };
        if gss_error(major) > 0 {
            let e = Error {
                major: unsafe { MajorFlags::from_bits_unchecked(major) },
                minor,
            };
            inner.state = ClientCtxState::Failed(e);
            Err(e)
        } else if major & _GSS_S_CONTINUE_NEEDED > 0 {
            inner.state = ClientCtxState::Partial;
            Ok(Some(out_tok))
        } else {
            inner.state = ClientCtxState::Complete;
            if out_tok.len() > 0 {
                Ok(Some(out_tok))
            } else {
                Ok(None)
            }
        }
    }
}

impl SecurityContext for ClientCtx {
    fn wrap(&self, encrypt: bool, msg: &[u8]) -> Result<Buf, Error> {
        let inner = self.0.lock();
        unsafe { wrap(inner.ctx, encrypt, msg) }
    }

    fn unwrap(&self, msg: &[u8]) -> Result<Buf, Error> {
        let inner = self.0.lock();
        unsafe { unwrap(inner.ctx, msg) }
    }

    fn info(&self) -> Result<CtxInfo, Error> {
        let inner = self.0.lock();
        unsafe { full_info(inner.ctx) }
    }

    fn source_name(&self) -> Result<Name, Error> {
        let inner = self.0.lock();
        unsafe { source_name(inner.ctx) }
    }

    fn target_name(&self) -> Result<Name, Error> {
        let inner = self.0.lock();
        unsafe { target_name(inner.ctx) }
    }

    fn lifetime(&self) -> Result<Duration, Error> {
        let inner = self.0.lock();
        unsafe { lifetime(inner.ctx) }
    }

    fn mechanism(&self) -> Result<&'static Oid, Error> {
        let inner = self.0.lock();
        unsafe { mechanism(inner.ctx) }
    }

    fn flags(&self) -> Result<CtxFlags, Error> {
        let inner = self.0.lock();
        unsafe { flags(inner.ctx) }
    }

    fn local(&self) -> Result<bool, Error> {
        let inner = self.0.lock();
        unsafe { local(inner.ctx) }
    }

    fn open(&self) -> Result<bool, Error> {
        let inner = self.0.lock();
        unsafe { open(inner.ctx) }
    }
}
