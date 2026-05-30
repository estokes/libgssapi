# libgssapi

A safe MIT licensed binding to gssapi

see [rfc2744](https://tools.ietf.org/html/rfc2744.html) for more info

gssapi is a huge and complex beast that is also very old (like [Computer Chronicles](https://youtu.be/wpXnqBfgvPM?list=PLR6RS8PTcoXT4g8SgQEww7QMe8Vtv5LKe) old). The Kerberos 5 mech is covered by an integration test suite (`tests/test.sh`) that runs the same in-process-KDC handshake and credential tests against all three supported implementations: MIT natively, Heimdal in a podman container, and the Apple GSS framework natively on macOS.

For a simpler cross platform interface to Kerberos 5 see [cross-krb5](https://crates.io/crates/cross-krb5).

### Features

**The default is empty.** None of the optional features build on every
implementation, so the only honest cross-platform default is no features —
each feature does exactly what it says, and enabling one the linked
implementation can't provide is a compile error, not a silent no-op. `all`
enables everything (MIT only).

- `iov` — `wrap_iov`/`unwrap_iov` and the `GssIov` types. **MIT + Heimdal**
  (Apple's GSS framework has no `gss_wrap_iov`).
- `localname` — `Name::local_name` (POSIX local-name mapping). **MIT +
  Heimdal** (Apple has no `gss_localname`).
- `store` — `Cred::store` (store into the default ccache). **MIT +
  Heimdal** (Apple has no `gss_store_cred`).
- `s4u` — Kerberos S4U constrained delegation (`Cred::impersonate`,
  `Cred::store_into`, impersonator lookup). **MIT only** — Heimdal and Apple
  implement neither `gss_acquire_cred_impersonate_name` nor
  `gss_store_cred_into`.

To enable a feature only where it's available, select it in a
target-specific dependency table rather than unconditionally:

```toml
[target.'cfg(not(target_os = "macos"))'.dependencies]
libgssapi = { version = "0.10", features = ["iov", "localname", "store"] }
```

### Build configuration

The build finds gssapi via `pkg-config` (preferring MIT over Heimdal),
falling back to searching standard library directories. Two env vars
override this:

- `LIBGSSAPI_IMPL` = `mit` | `heimdal` | `apple` — force the
  implementation. Handy when both MIT and Heimdal are installed.
- `LIBGSSAPI_PREFIX` = colon-separated install prefixes — for installs
  pkg-config can't find. Each prefix adds `<prefix>/include` to the
  header search and `<prefix>/lib` to the library search.

### Example KRB5 Mutual Authentication Between Client and Server

This is the `krb5` example verbatim (`libgssapi/examples/krb5.rs`); run it
with `cargo run --example krb5 -- nfs@host.example.com`. See the comment at
the top of that file for how to set up the Kerberos environment it needs.

```rust
use std::env::args;
use libgssapi::{
    name::Name,
    credential::{Cred, CredUsage},
    error::Error,
    context::{CtxFlags, ClientCtx, ServerCtx, SecurityContext},
    util::Buf,
    oid::{OidSet, GSS_NT_HOSTBASED_SERVICE, GSS_MECH_KRB5},
};

fn setup_server_ctx(
    service_name: &[u8],
    desired_mechs: &OidSet
) -> Result<(ServerCtx, Name), Error> {
    println!("import name");
    let name = Name::new(service_name, Some(GSS_NT_HOSTBASED_SERVICE))?;
    let cname = name.canonicalize(Some(GSS_MECH_KRB5))?;
    println!("canonicalize name for kerberos 5");
    println!("server name: {}, server cname: {}", name, cname);
    let server_cred = Cred::acquire(
        Some(&cname), None, CredUsage::Accept, Some(desired_mechs)
    )?;
    println!("acquired server credentials: {:#?}", server_cred.info()?);
    Ok((ServerCtx::new(Some(server_cred)), cname))
}

fn setup_client_ctx(
    service_name: Name,
    desired_mechs: &OidSet
) -> Result<ClientCtx, Error> {
    let client_cred = Cred::acquire(
        None, None, CredUsage::Initiate, Some(&desired_mechs)
    )?;
    println!("acquired default client credentials: {:#?}", client_cred.info()?);
    Ok(ClientCtx::new(
        Some(client_cred), service_name, CtxFlags::GSS_C_MUTUAL_FLAG, Some(GSS_MECH_KRB5)
    ))
}

fn run(service_name: &[u8]) -> Result<(), Error> {
    let desired_mechs = OidSet::singleton(GSS_MECH_KRB5)?;
    let (mut server_ctx, cname) = setup_server_ctx(service_name, &desired_mechs)?;
    let mut client_ctx = setup_client_ctx(cname, &desired_mechs)?;
    let mut server_tok: Option<Buf> = None;
    loop {
        match client_ctx.step(server_tok.as_ref().map(|b| &**b), None)? {
            None => break,
            Some(client_tok) => match server_ctx.step(&*client_tok, None)? {
                None => break,
                Some(tok) => { server_tok = Some(tok); }
            }
        }
    }
    println!("security context initialized successfully");
    println!("client ctx info: {:#?}", client_ctx.info()?);
    println!("server ctx info: {:#?}", server_ctx.info()?);
    let secret_msg = client_ctx.wrap(true, b"super secret message")?;
    let decoded_msg = server_ctx.unwrap(&*secret_msg)?;
    println!("the decrypted message is: '{}'", String::from_utf8_lossy(&*decoded_msg));
    Ok(())
}

fn main() {
    let args = args().collect::<Vec<_>>();
    if args.len() != 2 {
        println!("usage: {}: <service@host>", args[0]);
    } else {
        match run(&args[1].as_bytes()) {
            Ok(()) => (),
            Err(e) => println!("{}", e),
        }
    }
}
```
