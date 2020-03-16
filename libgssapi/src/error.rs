use crate::util::Buf;
use libgssapi_sys::{
    gss_display_status, OM_uint32, GSS_C_CALLING_ERROR_OFFSET, GSS_C_GSS_CODE,
    GSS_C_ROUTINE_ERROR_OFFSET, GSS_S_COMPLETE, _GSS_C_CALLING_ERROR_MASK,
    _GSS_C_ROUTINE_ERROR_MASK, gss_OID_desc,
};
use std::{fmt, ptr, error};

pub(crate) fn gss_error(x: OM_uint32) -> OM_uint32 {
    x & ((_GSS_C_CALLING_ERROR_MASK << GSS_C_CALLING_ERROR_OFFSET)
        | (_GSS_C_ROUTINE_ERROR_MASK << GSS_C_ROUTINE_ERROR_OFFSET))
}

#[derive(Clone, Copy, Debug)]
pub struct Error {
    pub major: u32,
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
                    buf.as_mut_ptr(),
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
        Error::fmt_code(f, self.major, "major")?;
        Ok(Error::fmt_code(f, self.minor, "minor")?)
    }
}

impl error::Error for Error {}
