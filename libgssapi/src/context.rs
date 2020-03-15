use crate::{
    credential::Cred,
    error::{gss_error, Error},
    name::Name,
    util::{Buf, BufRef},
};
use libgssapi_sys::{
    gss_OID, gss_accept_sec_context, gss_buffer_desc, gss_channel_bindings_struct,
    gss_cred_id_struct, gss_cred_id_t, gss_ctx_id_struct, gss_ctx_id_t,
    gss_delete_sec_context, gss_init_sec_context, gss_mech_krb5, gss_name_t, gss_wrap,
    OM_uint32, GSS_C_ANON_FLAG, GSS_C_CONF_FLAG, GSS_C_DELEG_FLAG,
    GSS_C_DELEG_POLICY_FLAG, GSS_C_INTEG_FLAG, GSS_C_MUTUAL_FLAG, GSS_C_PROT_READY_FLAG,
    GSS_C_QOP_DEFAULT, GSS_C_REPLAY_FLAG, GSS_C_SEQUENCE_FLAG, GSS_C_TRANS_FLAG,
    GSS_S_COMPLETE, _GSS_C_INDEFINITE, _GSS_S_CONTINUE_NEEDED, _GSS_S_NO_CONTEXT,
};
use parking_lot::Mutex;
use std::{ptr, sync::Arc};

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

fn wrap(ctx: gss_ctx_id_t, encrypt: bool, msg: &[u8]) -> Result<Buf, Error> {
    let mut minor = GSS_S_COMPLETE;
    let mut msg = BufRef::from(msg);
    let mut enc_msg = Buf::empty();
    let major = unsafe {
        gss_wrap(
            &mut minor as *mut OM_uint32,
            ctx,
            if encrypt { 1 } else { 0 },
            GSS_C_QOP_DEFAULT,
            msg.as_mut_ptr(),
            ptr::null_mut(),
            enc_msg.as_mut_ptr(),
        )
    };
    if gss_error(major) > 0 {
        Err(Error { major, minor })
    } else {
        Ok(enc_msg)
    }
}

pub trait SecurityContext {
    fn wrap(&self, encrypt: bool, msg: &[u8]) -> Result<Buf, Error>;
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
                    None => Some(Cred::from_raw(delegated_cred)),
                    Some(current) => {
                        if *current == delegated_cred {
                            Some(current)
                        } else {
                            Some(Cred::from_raw(delegated_cred))
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

impl SecurityContext for ServerCtx {
    fn wrap(&self, encrypt: bool, msg: &[u8]) -> Result<Buf, Error> {
        let inner = self.0.lock();
        let ctx = match *inner {
            ServerCtxInner::Failed(e) => return Err(e),
            ServerCtxInner::Uninit(_) => {
                return Err(Error {
                    major: _GSS_S_NO_CONTEXT,
                    minor: 0,
                })
            }
            ServerCtxInner::Partial { ctx, .. } => ctx,
            ServerCtxInner::Complete { ctx, .. } => ctx,
        };
        wrap(ctx, encrypt, msg)
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
                    Some(ref mut tok) => tok.as_mut_ptr(),
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

impl SecurityContext for ClientCtx {
    fn wrap(&self, encrypt: bool, msg: &[u8]) -> Result<Buf, Error> {
        let inner = self.0.lock();
        let ctx = match *inner {
            ClientCtxInner::Uninit { .. } => {
                return Err(Error {
                    major: _GSS_S_NO_CONTEXT,
                    minor: 0,
                })
            }
            ClientCtxInner::Failed(e) => return Err(e),
            ClientCtxInner::Partial { ctx, .. } => ctx,
            ClientCtxInner::Complete(ctx) => ctx,
        };
        wrap(ctx, encrypt, msg)
    }
}
