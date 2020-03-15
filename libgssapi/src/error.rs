
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
