#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(target_os = "macos")]
pub unsafe fn gss_wrap_iov(
    arg1: *mut OM_uint32,
    arg2: gss_ctx_id_t,
    arg3: ::std::os::raw::c_int,
    arg4: gss_qop_t,
    arg5: *mut ::std::os::raw::c_int,
    arg6: *mut gss_iov_buffer_desc,
    arg7: ::std::os::raw::c_int,
) -> OM_uint32 {
    __ApplePrivate_gss_wrap_iov(arg1, arg2, arg3, arg4, arg5, arg6, arg7)
}

#[cfg(target_os = "macos")]
pub unsafe fn gss_unwrap_iov(
    arg1: *mut OM_uint32,
    arg2: gss_ctx_id_t,
    arg3: *mut ::std::os::raw::c_int,
    arg4: *mut gss_qop_t,
    arg5: *mut gss_iov_buffer_desc,
    arg6: ::std::os::raw::c_int,
) -> OM_uint32 {
    __ApplePrivate_gss_unwrap_iov(arg1, arg2, arg3, arg4, arg5, arg6)
}

#[cfg(target_os = "macos")]
pub unsafe fn gss_wrap_iov_length(
    arg1: *mut OM_uint32,
    arg2: gss_ctx_id_t,
    arg3: ::std::os::raw::c_int,
    arg4: gss_qop_t,
    arg5: *mut ::std::os::raw::c_int,
    arg6: *mut gss_iov_buffer_desc,
    arg7: ::std::os::raw::c_int,
) -> OM_uint32 {
    __ApplePrivate_gss_wrap_iov_length(arg1, arg2, arg3, arg4, arg5, arg6, arg7)
}
