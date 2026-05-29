# libgssapi

A safe MIT licensed binding to gssapi

see [rfc2744](https://tools.ietf.org/html/rfc2744.html) for more info

gssapi is a huge and complex beast that is also very old (like [Computer Chronicles](https://youtu.be/wpXnqBfgvPM?list=PLR6RS8PTcoXT4g8SgQEww7QMe8Vtv5LKe) old). The Kerberos 5 mech is covered by an integration test suite (`tests/test.sh`) that runs against MIT natively and Heimdal in a podman container; the Apple GSS framework is supported on macOS but not currently in the automated suite.

For a simpler cross platform interface to Kerberos 5 see [cross-krb5](https://crates.io/crates/cross-krb5).

### Features

Default: `iov`, `localname`, `store`. `all` additionally enables `s4u`.

- `iov` — `wrap_iov`/`unwrap_iov` and the `GssIov` types.
- `localname` — `Name::local_name` (POSIX local-name mapping).
- `store` — `Cred::store` (store into the default ccache).
- `s4u` — Kerberos S4U constrained delegation (`Cred::impersonate`,
  `Cred::store_into`, impersonator lookup). **MIT only.** Heimdal does not
  implement `gss_acquire_cred_impersonate_name` / `gss_store_cred_into`, so
  enabling `s4u` (or `all`) against Heimdal will not compile. Use the
  default features on Heimdal.

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
```rust
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
    desired_mechs: &OidSet,
) -> Result<(ServerCtx, Name), Error> {
    let name = Name::new(service_name, Some(GSS_NT_HOSTBASED_SERVICE))?;
    let cname = name.canonicalize(Some(GSS_MECH_KRB5))?;
    let server_cred = Cred::acquire(
        Some(&cname), None, CredUsage::Accept, Some(desired_mechs),
    )?;
    Ok((ServerCtx::new(Some(server_cred)), cname))
}

fn setup_client_ctx(
    target: Name,
    desired_mechs: &OidSet,
) -> Result<ClientCtx, Error> {
    let client_cred = Cred::acquire(
        None, None, CredUsage::Initiate, Some(desired_mechs),
    )?;
    Ok(ClientCtx::new(
        Some(client_cred), target, CtxFlags::GSS_C_MUTUAL_FLAG, Some(GSS_MECH_KRB5),
    ))
}

fn run(service_name: &[u8]) -> Result<(), Error> {
    let desired_mechs = {
        let mut s = OidSet::new();
        s.add(GSS_MECH_KRB5)?;
        s
    };
    let (mut server_ctx, cname) = setup_server_ctx(service_name, &desired_mechs)?;
    let mut client_ctx = setup_client_ctx(cname, &desired_mechs)?;
    let mut server_tok: Option<Buf> = None;
    loop {
        match client_ctx.step(server_tok.as_ref().map(|b| &**b), None)? {
            None => break,
            Some(client_tok) => match server_ctx.step(&*client_tok)? {
                None => break,
                Some(tok) => { server_tok = Some(tok); }
            }
        }
    }
    let secret_msg = client_ctx.wrap(true, b"super secret message")?;
    let decoded_msg = server_ctx.unwrap(&*secret_msg)?;
    println!("decrypted: {}", String::from_utf8_lossy(&decoded_msg));
    Ok(())
}
```
