use crate::util::Buf;
use libgssapi_sys::{
    gss_OID_desc, gss_display_status, OM_uint32, GSS_C_CALLING_ERROR_OFFSET,
    GSS_C_GSS_CODE, GSS_C_ROUTINE_ERROR_OFFSET, GSS_S_COMPLETE,
    _GSS_C_CALLING_ERROR_MASK, _GSS_C_ROUTINE_ERROR_MASK, _GSS_S_BAD_BINDINGS,
    _GSS_S_BAD_MECH, _GSS_S_BAD_MECH_ATTR, _GSS_S_BAD_MIC, _GSS_S_BAD_NAME,
    _GSS_S_BAD_NAMETYPE, _GSS_S_BAD_QOP, _GSS_S_BAD_SIG, _GSS_S_BAD_STATUS,
    _GSS_S_CALL_BAD_STRUCTURE, _GSS_S_CALL_INACCESSIBLE_READ,
    _GSS_S_CALL_INACCESSIBLE_WRITE, _GSS_S_CONTEXT_EXPIRED, _GSS_S_CONTINUE_NEEDED,
    _GSS_S_CREDENTIALS_EXPIRED, _GSS_S_DEFECTIVE_CREDENTIAL, _GSS_S_DEFECTIVE_TOKEN,
    _GSS_S_DUPLICATE_ELEMENT, _GSS_S_DUPLICATE_TOKEN, _GSS_S_FAILURE, _GSS_S_GAP_TOKEN,
    _GSS_S_NAME_NOT_MN, _GSS_S_NO_CONTEXT, _GSS_S_NO_CRED, _GSS_S_OLD_TOKEN,
    _GSS_S_UNAUTHORIZED, _GSS_S_UNAVAILABLE, _GSS_S_UNSEQ_TOKEN,
};
use std::{error, fmt, ptr};

bitflags! {
    pub struct MajorFlags: u32 {
        // calling errors
        const GSS_S_CALL_INACCESSIBLE_READ = _GSS_S_CALL_INACCESSIBLE_READ;
        const GSS_S_CALL_INACCESSIBLE_WRITE = _GSS_S_CALL_INACCESSIBLE_WRITE;
        const GSS_S_CALL_BAD_STRUCTURE = _GSS_S_CALL_BAD_STRUCTURE;

        // routine errors
        const GSS_S_BAD_MECH = _GSS_S_BAD_MECH;
        const GSS_S_BAD_NAME = _GSS_S_BAD_NAME;
        const GSS_S_BAD_NAMETYPE = _GSS_S_BAD_NAMETYPE;
        const GSS_S_BAD_BINDINGS = _GSS_S_BAD_BINDINGS;
        const GSS_S_BAD_STATUS = _GSS_S_BAD_STATUS;
        const GSS_S_BAD_SIG = _GSS_S_BAD_SIG;
        const GSS_S_BAD_MIC = _GSS_S_BAD_MIC;
        const GSS_S_NO_CRED = _GSS_S_NO_CRED;
        const GSS_S_NO_CONTEXT = _GSS_S_NO_CONTEXT;
        const GSS_S_DEFECTIVE_TOKEN = _GSS_S_DEFECTIVE_TOKEN;
        const GSS_S_DEFECTIVE_CREDENTIAL = _GSS_S_DEFECTIVE_CREDENTIAL;
        const GSS_S_CREDENTIALS_EXPIRED = _GSS_S_CREDENTIALS_EXPIRED;
        const GSS_S_CONTEXT_EXPIRED = _GSS_S_CONTEXT_EXPIRED;
        const GSS_S_FAILURE = _GSS_S_FAILURE;
        const GSS_S_BAD_QOP = _GSS_S_BAD_QOP;
        const GSS_S_UNAUTHORIZED = _GSS_S_UNAUTHORIZED;
        const GSS_S_UNAVAILABLE = _GSS_S_UNAVAILABLE;
        const GSS_S_DUPLICATE_ELEMENT = _GSS_S_DUPLICATE_ELEMENT;
        const GSS_S_NAME_NOT_MN = _GSS_S_NAME_NOT_MN;
        const GSS_S_BAD_MECH_ATTR = _GSS_S_BAD_MECH_ATTR;

        // Supplementary info
        const GSS_S_CONTINUE_NEEDED = _GSS_S_CONTINUE_NEEDED;
        const GSS_S_DUPLICATE_TOKEN = _GSS_S_DUPLICATE_TOKEN;
        const GSS_S_OLD_TOKEN = _GSS_S_OLD_TOKEN;
        const GSS_S_UNSEQ_TOKEN = _GSS_S_UNSEQ_TOKEN;
        const GSS_S_GAP_TOKEN = _GSS_S_GAP_TOKEN;
    }
}

pub(crate) fn gss_error(x: OM_uint32) -> OM_uint32 {
    x & ((_GSS_C_CALLING_ERROR_MASK << GSS_C_CALLING_ERROR_OFFSET)
        | (_GSS_C_ROUTINE_ERROR_MASK << GSS_C_ROUTINE_ERROR_OFFSET))
}

#[derive(Clone, Copy, Debug)]
pub struct Error {
    pub major: MajorFlags,
    pub minor: u32,
}

impl Error {
    fn fmt_code(f: &mut fmt::Formatter<'_>, code: u32, name: &str) -> fmt::Result {
        let mut message_context: OM_uint32 = 0;
        loop {
            let mut minor = GSS_S_COMPLETE as OM_uint32;
            let mut buf = Buf::empty();
            let major = unsafe {
                gss_display_status(
                    &mut minor as *mut OM_uint32,
                    code,
                    GSS_C_GSS_CODE as i32,
                    ptr::null_mut::<gss_OID_desc>(),
                    &mut message_context as *mut OM_uint32,
                    buf.to_c(),
                )
            };
            if major == GSS_S_COMPLETE {
                let s = String::from_utf8_lossy(&*buf);
                let res = write!(f, "gssapi {} error {}\n", name, s);
                res?
            } else {
                write!(f, "gssapi unknown {} error code {}\n", name, code)?;
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
        Error::fmt_code(f, self.major.bits(), "major")?;
        Ok(Error::fmt_code(f, self.minor, "minor")?)
    }
}

impl error::Error for Error {}
