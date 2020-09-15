# libgssapi

A safe MIT licensed binding to gssapi

see [rfc2744](https://tools.ietf.org/html/rfc2744.html) for more info

gssapi is a huge and complex beast that is also very old (like [Computer Chronicles](https://youtu.be/wpXnqBfgvPM?list=PLR6RS8PTcoXT4g8SgQEww7QMe8Vtv5LKe) old). So while this library might work for lots of mechanisms it has only been tested (so far) with Kerberos 5 using the MIT and Apple implementations.

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
    desired_mechs: &OidSet
) -> Result<(ServerCtx, Name), Error> {
    let name = Name::new(service_name, Some(&GSS_NT_HOSTBASED_SERVICE))?;
    let cname = name.canonicalize(Some(&GSS_MECH_KRB5))?;
    let server_cred = Cred::acquire(
        Some(&cname), None, CredUsage::Accept, Some(desired_mechs)
    )?;
    Ok((ServerCtx::new(&server_cred), cname))
}

fn run(service_name: &[u8]) -> Result<(), Error> {
    let desired_mechs = {
        let mut s = OidSet::new()?;
        s.add(&GSS_MECH_KRB5)?;
        s
    };
    let (server_ctx, cname) = setup_server_ctx(service_name, &desired_mechs)?;
    let client_cred = Cred::acquire(
        None, None, CredUsage::Initiate, Some(&desired_mechs)
    )?;
    let client_ctx = ClientCtx::new(
        &client_cred, service_name, CtxFlags::GSS_C_MUTUAL_FLAG, Some(&GSS_MECH_KRB5)
    ))
    let mut server_tok: Option<Buf> = None;
    loop {
        match client_ctx.step(server_tok.as_ref().map(|b| &**b))? {
            None => break,
            Some(client_tok) => match server_ctx.step(&*client_tok)? {
                None => break,
                Some(tok) => { server_tok = Some(tok); }
            }
        }
    }
    let secret_msg = client_ctx.wrap(true, b"super secret message")?;
    let decoded_msg = server_ctx.unwrap(&*secret_msg)?;
    Ok(())
}
```
