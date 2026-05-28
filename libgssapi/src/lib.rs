//! Gssapi is the standard way of using Kerberos to build and use
//! Kerberized services on unix. It has other uses, but Kerberos is by
//! far the most common (and making Kerberos work well is the focus of
//! this library).
//! 
//! For a simpler cross platform interface to Kerberos 5 see 
//! [cross-krb5](https://crates.io/crates/cross-krb5).
//!
//! ## Contexts
//!
//! Gssapi is used through contexts which are connected to each other
//! in a mechanism specific way. In the case of Kerberos once you have
//! a context set up you can use to to send and receive encrypted
//! messages that only the other side can read. Other mechanisms may
//! or may not provide this feature.
//!
//! * Initiate a new connection with a [`ClientCtx`](context/struct.ClientCtx.html)
//! * Accept a client connection with a [`ServerCtx`](context/struct.ServerCtx.html)
//! * Both types implement [`SecurityContext`](context/trait.SecurityContext.html)
//!
//! Unlike SSL Gssapi is completely independent of the transport. It
//! will give you tokens to send to the other side, and tell you when
//! the context is established, it's up to you to decide how the data
//! gets there.
//! 
//! ```
//! use std::env::args;
//! use libgssapi::{
//!     name::Name,
//!     credential::{Cred, CredUsage},
//!     error::Error,
//!     context::{CtxFlags, ClientCtx, ServerCtx, SecurityContext},
//!     util::Buf,
//!     oid::{OidSet, GSS_NT_HOSTBASED_SERVICE, GSS_MECH_KRB5},
//! };
//! 
//! fn setup_server_ctx(
//!     service_name: &[u8],
//!     desired_mechs: &OidSet
//! ) -> Result<(ServerCtx, Name), Error> {
//!     let name = Name::new(service_name, Some(GSS_NT_HOSTBASED_SERVICE))?;
//!     let cname = name.canonicalize(Some(GSS_MECH_KRB5))?;
//!     let server_cred = Cred::acquire(
//!         Some(&cname), None, CredUsage::Accept, Some(desired_mechs)
//!     )?;
//!     Ok((ServerCtx::new(Some(server_cred)), cname))
//! }
//! 
//! fn setup_client_ctx(
//!     service_name: Name,
//!     desired_mechs: &OidSet
//! ) -> Result<ClientCtx, Error> {
//!     let client_cred = Cred::acquire(
//!         None, None, CredUsage::Initiate, Some(&desired_mechs)
//!     )?;
//!     Ok(ClientCtx::new(
//!         Some(client_cred), service_name, CtxFlags::GSS_C_MUTUAL_FLAG, Some(GSS_MECH_KRB5)
//!     ))
//! }
//! 
//! fn run(service_name: &[u8]) -> Result<(), Error> {
//!     let desired_mechs = {
//!         let mut s = OidSet::new();
//!         s.add(GSS_MECH_KRB5)?;
//!         s
//!     };
//!     let (mut server_ctx, cname) = setup_server_ctx(service_name, &desired_mechs)?;
//!     let mut client_ctx = setup_client_ctx(cname, &desired_mechs)?;
//!     let mut server_tok: Option<Buf> = None;
//!     loop {
//!         match client_ctx.step(server_tok.as_ref().map(|b| &**b), None)? {
//!             None => break,
//!             Some(client_tok) => match server_ctx.step(&*client_tok)? {
//!                 None => break,
//!                 Some(tok) => { server_tok = Some(tok); }
//!             }
//!         }
//!     }
//!     let secret_msg = client_ctx.wrap(true, b"super secret message")?;
//!     let decoded_msg = server_ctx.unwrap(&*secret_msg)?;
//!     println!("the decrypted message is: '{}'", String::from_utf8_lossy(&*decoded_msg));
//!     Ok(())
//! }
//! ```
#![deny(unsafe_op_in_unsafe_fn)]

#[macro_use] extern crate bitflags;
#[macro_use] extern crate lazy_static;
 
pub mod oid;
pub mod error;
pub mod util;
pub mod name;
pub mod credential;
pub mod context;

#[cfg(test)]
mod pure_rust_tests {
    use crate::context::CtxFlags;
    use crate::oid::{OidSet, GSS_MECH_KRB5, GSS_NT_ANONYMOUS, GSS_NT_USER_NAME};
    use crate::util::BufRef;

    // Regression: the literal previously used `\01` which Rust parses as
    // `\0` + ASCII '1' (two bytes), not octal 1. The real RFC 2078 OID is
    // 6 bytes: 2b 06 01 05 06 03.
    #[test]
    fn anonymous_oid_has_correct_bytes() {
        assert_eq!(&*GSS_NT_ANONYMOUS, b"\x2b\x06\x01\x05\x06\x03");
    }

    #[test]
    fn empty_oidset_is_null_and_zero_len() {
        let s = OidSet::new();
        assert_eq!(s.len(), 0);
        assert!(!s.contains(GSS_MECH_KRB5).expect("contains on empty set"));
    }

    #[test]
    fn oid_equality_is_by_bytes() {
        assert_eq!(GSS_MECH_KRB5, GSS_MECH_KRB5);
        assert_ne!(GSS_MECH_KRB5, GSS_NT_USER_NAME);
    }

    #[test]
    fn oid_deref_to_ber_bytes() {
        let bytes: &[u8] = &*GSS_MECH_KRB5;
        assert!(!bytes.is_empty());
    }

    // Guards the (non_null, 0) branch in BufRef::deref against future
    // regressions that might re-introduce from_raw_parts on this path.
    #[test]
    fn empty_bufref_deref() {
        let buf = BufRef::from(&[] as &[u8]);
        assert!((&*buf).is_empty());
    }

    #[test]
    fn ctx_flags_retain_unknown_bits() {
        let f = CtxFlags::from_bits_retain(0x8000_0000);
        assert_eq!(f.bits(), 0x8000_0000);
    }
}

