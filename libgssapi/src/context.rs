#[cfg(feature = "iov")]
use crate::util::{GssIov, GssIovFake};
use crate::{
    credential::Cred,
    error::{gss_error, Error, MajorFlags},
    name::Name,
    oid::{Oid, NO_OID},
    util::{Buf, BufRef},
};
use libgssapi_sys::{
    gss_OID, gss_accept_sec_context, gss_buffer_desc, gss_channel_bindings_struct, gss_channel_bindings_t,
    gss_cred_id_struct, gss_cred_id_t, gss_ctx_id_t, gss_delete_sec_context,
    gss_init_sec_context, gss_inquire_context, gss_name_t, gss_unwrap, gss_wrap,
    OM_uint32, GSS_C_ANON_FLAG, GSS_C_CONF_FLAG, GSS_C_DELEG_FLAG,
    GSS_C_DELEG_POLICY_FLAG, GSS_C_INTEG_FLAG, GSS_C_MUTUAL_FLAG, GSS_C_PROT_READY_FLAG,
    GSS_C_QOP_DEFAULT, GSS_C_REPLAY_FLAG, GSS_C_SEQUENCE_FLAG, GSS_C_TRANS_FLAG,
    GSS_S_COMPLETE, _GSS_C_INDEFINITE, _GSS_S_CONTINUE_NEEDED,
};
#[cfg(feature = "iov")]
use libgssapi_sys::{
    gss_iov_buffer_desc, gss_unwrap_iov, gss_wrap_iov, gss_wrap_iov_length,
};
use std::{ffi, ptr, time::Duration};

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

#[cfg(feature = "iov")]
unsafe fn wrap_iov(
    ctx: gss_ctx_id_t,
    encrypt: bool,
    msg: &mut [GssIov],
) -> Result<(), Error> {
    let mut minor = GSS_S_COMPLETE;
    let major = gss_wrap_iov(
        &mut minor as *mut OM_uint32,
        ctx,
        if encrypt { 1 } else { 0 },
        GSS_C_QOP_DEFAULT,
        ptr::null_mut(),
        msg.as_mut_ptr() as *mut gss_iov_buffer_desc,
        msg.len() as i32,
    );
    if major == GSS_S_COMPLETE {
        Ok(())
    } else {
        Err(Error {
            major: MajorFlags::from_bits_unchecked(major),
            minor,
        })
    }
}

#[cfg(feature = "iov")]
unsafe fn wrap_iov_length(
    ctx: gss_ctx_id_t,
    encrypt: bool,
    msg: &mut [GssIovFake],
) -> Result<(), Error> {
    let mut minor = GSS_S_COMPLETE;
    let major = gss_wrap_iov_length(
        &mut minor as *mut OM_uint32,
        ctx,
        if encrypt { 1 } else { 0 },
        GSS_C_QOP_DEFAULT,
        ptr::null_mut(),
        msg.as_mut_ptr() as *mut gss_iov_buffer_desc,
        msg.len() as i32,
    );
    if major == GSS_S_COMPLETE {
        Ok(())
    } else {
        Err(Error {
            major: MajorFlags::from_bits_unchecked(major),
            minor,
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

#[cfg(feature = "iov")]
unsafe fn unwrap_iov(ctx: gss_ctx_id_t, msg: &mut [GssIov]) -> Result<(), Error> {
    let mut minor = GSS_S_COMPLETE;
    let major = gss_unwrap_iov(
        &mut minor as *mut OM_uint32,
        ctx,
        ptr::null_mut(),
        ptr::null_mut(),
        msg.as_mut_ptr() as *mut gss_iov_buffer_desc,
        msg.len() as i32,
    );
    if major == GSS_S_COMPLETE {
        Ok(())
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
    fn wrap(&mut self, encrypt: bool, msg: &[u8]) -> Result<Buf, Error>;

    /** From the MIT kerberos documentation,

    > Sign and optionally encrypt a sequence of buffers. The buffers
    > shall be ordered HEADER | DATA | PADDING | TRAILER. Suitable
    > space for the header, padding and trailer should be provided
    > by calling gss_wrap_iov_length(), or the ALLOCATE flag should
    > be set on those buffers.

    rust note: if you don't want to use the ALLOCATE flag then call
    `wrap_iov_length` with a set of `GssIovFake`
    objects. These don't contain any allocated memory, and can't be
    dererenced or used, but the C library will set their length. You
    then need to use those lengths to allocate the correct amount of
    memory for the real wrap_iov call.

    > Encryption is in-place. SIGN_ONLY buffers are untouched. Only
    > a single PADDING buffer should be provided. The order of the
    > buffers in memory does not matter. Buffers in the IOV should
    > be arranged in the order above, and in the case of multiple
    > DATA buffers the sender and receiver should agree on the
    > order.
    >
    > With GSS_C_DCE_STYLE it is acceptable to not provide PADDING
    > and TRAILER, but the caller must guarantee the plaintext data
    > being encrypted is correctly padded, otherwise an error will
    > be returned.
    >
    > While applications that have knowledge of the underlying
    > cryptosystem may request a specific configuration of data
    > buffers, the only generally supported configurations are:
    >
    > HEADER | DATA | PADDING | TRAILER
    >
    > which will emit GSS_Wrap() compatible tokens, and:
    >
    > HEADER | SIGN_ONLY | DATA | PADDING | TRAILER
    >
    > for AEAD.
    >
    > The typical (special cased) usage for DCE is as follows:
    >
    > SIGN_ONLY_1 | DATA | SIGN_ONLY_2 | HEADER
     */
    #[cfg(feature = "iov")]
    fn wrap_iov(&mut self, encrypt: bool, msg: &mut [GssIov]) -> Result<(), Error>;

    /// This will set the required length of all the buffers except
    /// the data buffer, which must be provided as it will be to
    /// wrap_iov. The value of the encrypt flag must match what you
    /// pass to `wrap_iov`.
    #[cfg(feature = "iov")]
    fn wrap_iov_length(
        &mut self,
        encrypt: bool,
        msg: &mut [GssIovFake],
    ) -> Result<(), Error>;

    /// Unwrap a wrapped message, checking it's integrity and
    /// decrypting it if necessary.
    fn unwrap(&mut self, msg: &[u8]) -> Result<Buf, Error>;

    /** From the MIT Kerberos documentation,

    > gss_unwrap_iov may be called with an IOV list just like one which
    > would be provided to gss_wrap_iov. DATA buffers will be decrypted
    > in-place if they were encrypted, and SIGN_ONLY buffers will not be
    > modified.

    > Alternatively, gss_unwrap_iov may be called with a single STREAM
    > buffer, zero or more SIGN_ONLY buffers, and a single DATA
    > buffer. The STREAM buffer is interpreted as a complete wrap
    > token. The STREAM buffer will be modified in-place to decrypt its
    > contents. The DATA buffer will be initialized to point to the
    > decrypted data within the STREAM buffer, unless it has the
    > GSS_C_BUFFER_FLAG_ALLOCATE flag set, in which case it will be
    > initialized with a copy of the decrypted data.
    */
    #[cfg(feature = "iov")]
    fn unwrap_iov(&mut self, msg: &mut [GssIov]) -> Result<(), Error>;

    /// Get all information about a security context in one call
    fn info(&mut self) -> Result<CtxInfo, Error>;

    /// Get the source name of the security context
    fn source_name(&mut self) -> Result<Name, Error>;

    /// Get the target name of the security context
    fn target_name(&mut self) -> Result<Name, Error>;

    /// Get the lifetime of the security context
    fn lifetime(&mut self) -> Result<Duration, Error>;

    /// Get the mechanism of the security context
    fn mechanism(&mut self) -> Result<&'static Oid, Error>;

    /// Get the flags of the security context
    fn flags(&mut self) -> Result<CtxFlags, Error>;

    /// Return true if the security context was locally initiated
    fn local(&mut self) -> Result<bool, Error>;

    /// Return true if the security context is open
    fn open(&mut self) -> Result<bool, Error>;
}

#[derive(Debug)]
enum ServerCtxState {
    Uninitialized,
    Failed(Error),
    Partial,
    Complete,
}

/// The server side of a security context
#[derive(Debug)]
pub struct ServerCtx {
    ctx: gss_ctx_id_t,
    cred: Cred,
    delegated_cred: Option<Cred>,
    flags: CtxFlags,
    state: ServerCtxState,
}

impl Drop for ServerCtx {
    fn drop(&mut self) {
        delete_ctx(self.ctx);
    }
}

unsafe impl Send for ServerCtx {}
unsafe impl Sync for ServerCtx {}

impl ServerCtx {
    /// Create a new uninitialized server context with the specified
    /// credentials. You must then call `step` until the context is
    /// fully initialized. The mechanism is not specified because it
    /// is dictated by the client.
    pub fn new(cred: Cred) -> ServerCtx {
        ServerCtx {
            ctx: ptr::null_mut(),
            cred,
            delegated_cred: None,
            flags: CtxFlags::empty(),
            state: ServerCtxState::Uninitialized,
        }
    }

    /// Perform 1 step in the initialization of the server context,
    /// feeding it a token you received from the client. If
    /// initialization is complete from the point of view of the
    /// server then this will return Ok(None). Otherwise it will
    /// return a token that needs to be sent to the client and fed to
    /// `ClientCtx::step`.
    pub fn step(&mut self, tok: &[u8]) -> Result<Option<Buf>, Error> {
        match self.state {
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
                &mut self.ctx as *mut gss_ctx_id_t,
                self.cred.to_c(),
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
            match &self.delegated_cred {
                None => unsafe {
                    self.delegated_cred = Some(Cred::from_c(delegated_cred));
                },
                Some(current) => unsafe {
                    if current.to_c() != delegated_cred {
                        self.delegated_cred = Some(Cred::from_c(delegated_cred));
                    }
                },
            }
        }
        if let Some(new_flags) = CtxFlags::from_bits(flag_bits) {
            self.flags.insert(new_flags);
        }
        if gss_error(major) > 0 {
            let e = Error {
                major: unsafe { MajorFlags::from_bits_unchecked(major) },
                minor,
            };
            self.state = ServerCtxState::Failed(e);
            Err(e)
        } else if major & _GSS_S_CONTINUE_NEEDED > 0 {
            self.state = ServerCtxState::Partial;
            Ok(Some(out_tok))
        } else {
            self.state = ServerCtxState::Complete;
            if out_tok.len() > 0 {
                Ok(Some(out_tok))
            } else {
                Ok(None)
            }
        }
    }
}

impl SecurityContext for ServerCtx {
    fn wrap(&mut self, encrypt: bool, msg: &[u8]) -> Result<Buf, Error> {
        unsafe { wrap(self.ctx, encrypt, msg) }
    }

    #[cfg(feature = "iov")]
    fn wrap_iov(&mut self, encrypt: bool, msg: &mut [GssIov]) -> Result<(), Error> {
        unsafe { wrap_iov(self.ctx, encrypt, msg) }
    }

    #[cfg(feature = "iov")]
    fn wrap_iov_length(
        &mut self,
        encrypt: bool,
        msg: &mut [GssIovFake],
    ) -> Result<(), Error> {
        unsafe { wrap_iov_length(self.ctx, encrypt, msg) }
    }

    fn unwrap(&mut self, msg: &[u8]) -> Result<Buf, Error> {
        unsafe { unwrap(self.ctx, msg) }
    }

    #[cfg(feature = "iov")]
    fn unwrap_iov(&mut self, msg: &mut [GssIov]) -> Result<(), Error> {
        unsafe { unwrap_iov(self.ctx, msg) }
    }

    fn info(&mut self) -> Result<CtxInfo, Error> {
        unsafe { full_info(self.ctx) }
    }

    fn source_name(&mut self) -> Result<Name, Error> {
        unsafe { source_name(self.ctx) }
    }

    fn target_name(&mut self) -> Result<Name, Error> {
        unsafe { target_name(self.ctx) }
    }

    fn lifetime(&mut self) -> Result<Duration, Error> {
        unsafe { lifetime(self.ctx) }
    }

    fn mechanism(&mut self) -> Result<&'static Oid, Error> {
        unsafe { mechanism(self.ctx) }
    }

    fn flags(&mut self) -> Result<CtxFlags, Error> {
        unsafe { flags(self.ctx) }
    }

    fn local(&mut self) -> Result<bool, Error> {
        unsafe { local(self.ctx) }
    }

    fn open(&mut self) -> Result<bool, Error> {
        unsafe { open(self.ctx) }
    }
}

#[derive(Debug)]
enum ClientCtxState {
    Uninitialized,
    Failed(Error),
    Partial,
    Complete,
}

/// The client side of a security context
#[derive(Debug)]
pub struct ClientCtx {
    ctx: gss_ctx_id_t,
    cred: Cred,
    target: Name,
    flags: CtxFlags,
    state: ClientCtxState,
    mech: Option<&'static Oid>,
    cbt: Option<Vec<u8>>,
}

impl Drop for ClientCtx {
    fn drop(&mut self) {
        delete_ctx(self.ctx);
    }
}

unsafe impl Send for ClientCtx {}
unsafe impl Sync for ClientCtx {}

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
        ClientCtx {
            ctx: ptr::null_mut(),
            cred,
            target,
            flags,
            state: ClientCtxState::Uninitialized,
            mech,
            cbt: None,
        }
    }

    /// Perform 1 step in the initialization of the specfied security
    /// context. Since the client initiates context creation, the
    /// token will initially be None, and gssapi will give you a token
    /// to send to the server. The server may send back a token, which
    /// you must feed to this function, and possibly get another token
    /// to send to the server. This will go on a mechanism specifiec
    /// number of times until step returns `Ok(None)`. At that point
    /// the context is fully initialized.
    pub fn step(&mut self, tok: Option<&[u8]>) -> Result<Option<Buf>, Error> {
        #[inline]
        fn empty_buffer() -> gss_buffer_desc {
            gss_buffer_desc {
                length: 0,
                value: ptr::null_mut(),
            }
        }

        match self.state {
            ClientCtxState::Uninitialized | ClientCtxState::Partial => (),
            ClientCtxState::Failed(e) => return Err(e),
            ClientCtxState::Complete => return Ok(None),
        };
        let mut cbs = gss_channel_bindings_struct {
            initiator_addrtype: 0,
            initiator_address: empty_buffer(),
            acceptor_addrtype: 0,
            acceptor_address: empty_buffer(),
            application_data: empty_buffer(),
        };
        let bindings = if let Some(cbt) = &self.cbt {
            cbs.application_data = gss_buffer_desc {
                length: cbt.len() as u64,
                value: cbt.as_ptr() as *mut ffi::c_void,
            };
            &mut cbs as gss_channel_bindings_t
        } else {
            ptr::null_mut::<gss_channel_bindings_struct>()
        };
        let mut minor = GSS_S_COMPLETE;
        let mut tok = tok.map(BufRef::from);
        let mut out_tok = Buf::empty();
        let major = unsafe {
            gss_init_sec_context(
                &mut minor as *mut OM_uint32,
                self.cred.to_c(),
                &mut self.ctx as *mut gss_ctx_id_t,
                self.target.to_c(),
                match self.mech {
                    None => NO_OID,
                    Some(mech) => mech.to_c(),
                },
                self.flags.bits(),
                _GSS_C_INDEFINITE,
                bindings,
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
        self.cbt = None;
        if gss_error(major) > 0 {
            let e = Error {
                major: unsafe { MajorFlags::from_bits_unchecked(major) },
                minor,
            };
            self.state = ClientCtxState::Failed(e);
            Err(e)
        } else if major & _GSS_S_CONTINUE_NEEDED > 0 {
            self.state = ClientCtxState::Partial;
            Ok(Some(out_tok))
        } else {
            self.state = ClientCtxState::Complete;
            if out_tok.len() > 0 {
                Ok(Some(out_tok))
            } else {
                Ok(None)
            }
        }
    }

    /// Set the channel binding token which will be incorporated
    /// into the next generated GSSAPI token. Channel bindings are opaque
    /// structures whose content is dictated by the application.
    ///
    /// The channel binding token is "spent" after the `step()` call
    /// on the context. If you need it for another step, you must
    /// set it again.
    pub fn set_cb_token(&mut self, cbt: Vec<u8>) {
        self.cbt = Some(cbt);
    }
}

impl SecurityContext for ClientCtx {
    fn wrap(&mut self, encrypt: bool, msg: &[u8]) -> Result<Buf, Error> {
        unsafe { wrap(self.ctx, encrypt, msg) }
    }

    #[cfg(feature = "iov")]
    fn wrap_iov(&mut self, encrypt: bool, msg: &mut [GssIov]) -> Result<(), Error> {
        unsafe { wrap_iov(self.ctx, encrypt, msg) }
    }

    #[cfg(feature = "iov")]
    fn wrap_iov_length(
        &mut self,
        encrypt: bool,
        msg: &mut [GssIovFake],
    ) -> Result<(), Error> {
        unsafe { wrap_iov_length(self.ctx, encrypt, msg) }
    }

    fn unwrap(&mut self, msg: &[u8]) -> Result<Buf, Error> {
        unsafe { unwrap(self.ctx, msg) }
    }

    #[cfg(feature = "iov")]
    fn unwrap_iov(&mut self, msg: &mut [GssIov]) -> Result<(), Error> {
        unsafe { unwrap_iov(self.ctx, msg) }
    }

    fn info(&mut self) -> Result<CtxInfo, Error> {
        unsafe { full_info(self.ctx) }
    }

    fn source_name(&mut self) -> Result<Name, Error> {
        unsafe { source_name(self.ctx) }
    }

    fn target_name(&mut self) -> Result<Name, Error> {
        unsafe { target_name(self.ctx) }
    }

    fn lifetime(&mut self) -> Result<Duration, Error> {
        unsafe { lifetime(self.ctx) }
    }

    fn mechanism(&mut self) -> Result<&'static Oid, Error> {
        unsafe { mechanism(self.ctx) }
    }

    fn flags(&mut self) -> Result<CtxFlags, Error> {
        unsafe { flags(self.ctx) }
    }

    fn local(&mut self) -> Result<bool, Error> {
        unsafe { local(self.ctx) }
    }

    fn open(&mut self) -> Result<bool, Error> {
        unsafe { open(self.ctx) }
    }
}
