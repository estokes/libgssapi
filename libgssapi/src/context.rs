use crate::{
    credential::Cred,
    error::{gss_error, Error},
    name::Name,
    util::{Buf, BufRef},
};
use libgssapi_sys::{
    gss_OID, gss_accept_sec_context, gss_buffer_desc, gss_channel_bindings_struct,
    gss_cred_id_struct, gss_cred_id_t, gss_ctx_id_t,
    gss_delete_sec_context, gss_init_sec_context, gss_mech_krb5, gss_name_t, gss_wrap,
    gss_unwrap,
    OM_uint32, GSS_C_ANON_FLAG, GSS_C_CONF_FLAG, GSS_C_DELEG_FLAG,
    GSS_C_DELEG_POLICY_FLAG, GSS_C_INTEG_FLAG, GSS_C_MUTUAL_FLAG, GSS_C_PROT_READY_FLAG,
    GSS_C_QOP_DEFAULT, GSS_C_REPLAY_FLAG, GSS_C_SEQUENCE_FLAG, GSS_C_TRANS_FLAG,
    GSS_S_COMPLETE, _GSS_C_INDEFINITE, _GSS_S_CONTINUE_NEEDED,
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
    dbg!("delete ctx");
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
    if major == GSS_S_COMPLETE {
        Ok(enc_msg)
    } else {
        Err(Error { major, minor })
    }
}

fn unwrap(ctx: gss_ctx_id_t, msg: &[u8]) -> Result<Buf, Error> {
    let mut minor = GSS_S_COMPLETE;
    let mut msg = BufRef::from(msg);
    let mut out = Buf::empty();
    let major = unsafe {
        gss_unwrap(
            &mut minor as *mut OM_uint32,
            ctx,
            msg.as_mut_ptr(),
            out.as_mut_ptr(),
            ptr::null_mut::<i32>(),
            ptr::null_mut::<OM_uint32>()
        )
    };
    if major == GSS_S_COMPLETE {
        Ok(out)
    } else {
        Err(Error {major, minor})
    }
}

pub trait SecurityContext {
    fn wrap(&self, encrypt: bool, msg: &[u8]) -> Result<Buf, Error>;
    fn unwrap(&self, msg: &[u8]) -> Result<Buf, Error>;
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

#[derive(Clone)]
pub struct ServerCtx(Arc<Mutex<ServerCtxInner>>);

impl ServerCtx {
    pub fn new(cred: &Cred) -> ServerCtx {
        ServerCtx(Arc::new(Mutex::new(ServerCtxInner {
            ctx: ptr::null_mut(),
            cred: cred.clone(),
            delegated_cred: None,
            flags: CtxFlags::empty(),
            state: ServerCtxState::Uninitialized,
        })))
    }

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
                *inner.cred,
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
        if !delegated_cred.is_null() {
            match &inner.delegated_cred {
                None => {
                    inner.delegated_cred = Some(Cred::from_raw(delegated_cred));
                }
                Some(current) => {
                    if **current != delegated_cred {
                        inner.delegated_cred = Some(Cred::from_raw(delegated_cred));
                    }
                }
            }
        }
        if let Some(new_flags) = CtxFlags::from_bits(flag_bits) {
            inner.flags.insert(new_flags);
        }
        if gss_error(major) > 0 {
            let e = Error { major, minor };
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
        wrap(inner.ctx, encrypt, msg)
    }

    fn unwrap(&self, msg: &[u8]) -> Result<Buf, Error> {
        let inner = self.0.lock();
        unwrap(inner.ctx, msg)
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
}

impl Drop for ClientCtxInner {
    fn drop(&mut self) {
        delete_ctx(self.ctx);
    }
}

#[derive(Clone)]
pub struct ClientCtx(Arc<Mutex<ClientCtxInner>>);

impl ClientCtx {
    pub fn new(cred: &Cred, target: &Name, flags: CtxFlags) -> ClientCtx {
        let inner = ClientCtxInner {
            ctx: ptr::null_mut(),
            cred: cred.clone(),
            target: target.clone(),
            flags,
            state: ClientCtxState::Uninitialized,
        };
        ClientCtx(Arc::new(Mutex::new(inner)))
    }

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
                *inner.cred,
                &mut inner.ctx as *mut gss_ctx_id_t,
                *inner.target,
                gss_mech_krb5,
                inner.flags.bits(),
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
        wrap(inner.ctx, encrypt, msg)
    }

    fn unwrap(&self, msg: &[u8]) -> Result<Buf, Error> {
        let inner = self.0.lock();
        unwrap(inner.ctx, msg)
    }
}
