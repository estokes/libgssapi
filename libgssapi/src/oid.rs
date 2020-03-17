/// Oids are BER encoded and defined in the various RFCs
use libgssapi_sys::{gss_OID, gss_OID_desc};
use std::{
    self,
    cmp::{Eq, PartialEq},
    mem,
};

// CR estokes: do I need the attributes from rfc 5587? There are loads of them.
static GSS_C_NT_USER_NAME_BER: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01";
pub static GSS_C_NT_USER_NAME: Oid = Oid {
    length: GSS_C_NT_USER_NAME_BER.len() as u32,
    elements: GSS_C_NT_USER_NAME_BER.as_ptr(),
};

static GSS_C_NT_MACHINE_UID_NAME_BER: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x02";
pub static GSS_C_NT_MACHINE_UID_NAME: Oid = Oid {
    length: GSS_C_NT_MACHINE_UID_NAME_BER.len() as u32,
    elements: GSS_C_NT_MACHINE_UID_NAME_BER.as_ptr(),
};

static GSS_C_NT_STRING_UID_NAME_BER: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x03";
pub static GSS_C_NT_STRING_UID_NAME: Oid = Oid {
    length: GSS_C_NT_STRING_UID_NAME_BER.len() as u32,
    elements: GSS_C_NT_STRING_UID_NAME_BER.as_ptr(),
};

static GSS_C_NT_HOSTBASED_SERVICE_BER: &[u8] =
    b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04";
pub static GSS_C_NT_HOSTBASED_SERVICE: Oid = Oid {
    length: GSS_C_NT_HOSTBASED_SERVICE_BER.len() as u32,
    elements: GSS_C_NT_HOSTBASED_SERVICE_BER.as_ptr(),
};

static GSS_C_NT_ANONYMOUS_BER: &[u8] = b"\x2b\x06\01\x05\x06\x03";
pub static GSS_C_NT_ANONYMOUS: Oid = Oid {
    length: GSS_C_NT_ANONYMOUS_BER.len() as u32,
    elements: GSS_C_NT_ANONYMOUS_BER.as_ptr(),
};

static GSS_C_NT_EXPORT_NAME_BER: &[u8] = b"\x2b\x06\x01\x05\x06\x04";
pub static GSS_C_NT_EXPORT_NAME: Oid = Oid {
    length: GSS_C_NT_EXPORT_NAME_BER.len() as u32,
    elements: GSS_C_NT_EXPORT_NAME_BER.as_ptr(),
};

static GSS_C_NT_COMPOSITE_EXPORT_BER: &[u8] = b"\x2b\x06\x01\x05\x06\x06";
pub static GSS_C_NT_COMPOSITE_EXPORT: Oid = Oid {
    length: GSS_C_NT_COMPOSITE_EXPORT_BER.len() as u32,
    elements: GSS_C_NT_COMPOSITE_EXPORT_BER.as_ptr(),
};

static GSS_C_INQ_SSPI_SESSION_KEY_BER: &[u8] =
    b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05";
pub static GSS_C_INQ_SSPI_SESSION_KEY: Oid = Oid {
    length: GSS_C_INQ_SSPI_SESSION_KEY_BER.len() as u32,
    elements: GSS_C_INQ_SSPI_SESSION_KEY_BER.as_ptr(),
};

static GSS_C_INQ_NEGOEX_KEY_BER: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x10";
pub static GSS_C_INQ_NEGOEX_KEY: Oid = Oid {
    length: GSS_C_INQ_NEGOEX_KEY_BER.len() as u32,
    elements: GSS_C_INQ_NEGOEX_KEY_BER.as_ptr(),
};

static GSS_C_INQ_NEGOEX_VERIFY_KEY_BER: &[u8] =
    b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x11";
pub static GSS_C_INQ_NEGOEX_VERIFY_KEY: Oid = Oid {
    length: GSS_C_INQ_NEGOEX_VERIFY_KEY_BER.len() as u32,
    elements: GSS_C_INQ_NEGOEX_VERIFY_KEY_BER.as_ptr(),
};

static GSS_C_MA_NEGOEX_AND_SPNEGO_BER: &[u8] =
    b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x12";
pub static GSS_C_MA_NEGOEX_AND_SPNEGO: Oid = Oid {
    length: GSS_C_MA_NEGOEX_AND_SPNEGO_BER.len() as u32,
    elements: GSS_C_MA_NEGOEX_AND_SPNEGO_BER.as_ptr(),
};

static GSS_SEC_CONTEXT_SASL_SSF_OID_BER: &[u8] =
    b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x0f";
pub static GSS_SEC_CONTEXT_SASL_SSF_OID: Oid = Oid {
    length: GSS_SEC_CONTEXT_SASL_SSF_OID_BER.len() as u32,
    elements: GSS_SEC_CONTEXT_SASL_SSF_OID_BER.as_ptr(),
};

static GSS_MECH_KRB5_OID_BER: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";
pub static GSS_MECH_KRB5_OID: Oid = Oid {
    length: GSS_MECH_KRB5_OID_BER.len() as u32,
    elements: GSS_MECH_KRB5_OID_BER.as_ptr(),
};

static GSS_MECH_IAKERB_OID_BER: &[u8] = b"\x2b\x06\x01\x05\x02\x05";
pub static GSS_MECH_IAKERB_OID: Oid = Oid {
    length: GSS_MECH_IAKERB_OID_BER.len() as u32,
    elements: GSS_MECH_IAKERB_OID_BER.as_ptr(),
};

static GSS_KRB5_NT_PRINCIPAL_NAME_BER: &[u8] =
    b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x01";
pub static GSS_KRB5_NT_PRINCIPAL_NAME: Oid = Oid {
    length: GSS_KRB5_NT_PRINCIPAL_NAME_BER.len() as u32,
    elements: GSS_KRB5_NT_PRINCIPAL_NAME_BER.as_ptr(),
};

static GSS_KRB5_CRED_NO_CI_FLAGS_X_BER: &[u8] = b"\x2a\x85\x70\x2b\x0d\x1d";
pub static GSS_KRB5_CRED_NO_CI_FLAGS_X: Oid = Oid {
    length: GSS_KRB5_CRED_NO_CI_FLAGS_X_BER.len() as u32,
    elements: GSS_KRB5_CRED_NO_CI_FLAGS_X_BER.as_ptr(),
};

static GSS_KRB5_GET_CRED_IMPERSONATOR_BER: &[u8] =
    b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x0e";
pub static GSS_KRB5_GET_CRED_IMPERSONATOR: Oid = Oid {
    length: GSS_KRB5_GET_CRED_IMPERSONATOR_BER.len() as u32,
    elements: GSS_KRB5_GET_CRED_IMPERSONATOR_BER.as_ptr(),
};

// this mirrors the C struct, but has a proper const pointer AS
// SPECIFIED in the standard. This ends up being, sadly, the most
// ergonomic way of wrapping the api.
#[repr(C)]
pub struct Oid {
    length: u32,
    elements: *const u8,
}

unsafe impl Sync for Oid {}

impl From<&'static [u8]> for Oid {
    fn from(octets: &[u8]) -> Self {
        Oid {
            length: octets.len() as u32,
            elements: octets.as_ptr(),
        }
    }
}

impl From<gss_OID_desc> for Oid {
    fn from(oid: gss_OID_desc) -> Self {
        Oid {
            length: oid.length,
            elements: unsafe { mem::transmute::<*mut std::ffi::c_void, _>(oid.elements) }
        }
    }
}

impl Oid {
    pub(crate) fn from_c(ptr: gss_OID) -> Option<&'static Oid> {
        unsafe {
            mem::transmute::<gss_OID, *const Oid>(ptr).as_ref()
        }
    }

    pub(crate) fn to_c(&self) -> gss_OID {
        unsafe {
            mem::transmute::<*const Oid, gss_OID>(self as *const Oid)
        }
    }
}
