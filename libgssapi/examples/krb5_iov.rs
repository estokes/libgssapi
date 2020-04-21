/* This is exactly the same as the krb5 example (see the top of that
 * program for a detailed description of how to run it and what you
 * should see when you do run it), however it demonstrates using
 * wrap_iov, and unwrap_iov to do in place encryption/decryption. */

use std::env::args;
use bytes::{BytesMut, Bytes, Buf, BufMut};
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
    let name = Name::new(service_name, Some(&GSS_NT_HOSTBASED_SERVICE))?;
    let cname = name.canonicalize(Some(&GSS_MECH_KRB5))?;
    println!("canonicalize name for kerberos 5");
    println!("server name: {}, server cname: {}", name, cname);
    let server_cred = Cred::acquire(
        Some(&cname), None, CredUsage::Accept, Some(desired_mechs)
    )?;
    println!("acquired server credentials: {:#?}", server_cred.info()?);
    Ok((ServerCtx::new(server_cred), cname))
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
        client_cred, service_name, CtxFlags::GSS_C_MUTUAL_FLAG, Some(&GSS_MECH_KRB5)
    ))
}

fn run(service_name: &[u8]) -> Result<(), Error> {
    let desired_mechs = {
        let mut s = OidSet::new()?;
        s.add(&GSS_MECH_KRB5)?;
        s
    };
    let (server_ctx, cname) = setup_server_ctx(service_name, &desired_mechs)?;
    let client_ctx = setup_client_ctx(cname, &desired_mechs)?;
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
