//! The abstract model of gssapi is client/server, there is always the
//! idea of a client that is going to create a `context` with some
//! server. The process of creating the context will mutually
//! authenticate the client and the server to each other, and they can
//! then use it to exchange encrypted, and/or integrity checked
//! messages for some period of time while the context is valid. So if
//! you're lost start in the context module.
#[macro_use] extern crate bitflags;
#[macro_use] extern crate lazy_static;

pub mod oid;
pub mod error;
pub mod util;
pub mod name;
pub mod credential;
pub mod context;
