use libgssapi_sys::*;
use std::ops::Drop;

pub struct Name {
    inner: gss_name_t
}

impl Drop for Name {
    fn drop(&mut self) {
    }
}

impl Name {
}

pub struct Credential {
    inner: gss_cred_id_t
}

