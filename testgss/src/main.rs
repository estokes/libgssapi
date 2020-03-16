use std::ops::Deref;
use libgssapi::{
    name::Name,
    credential::{Cred, CredUsage},
    error::Error,
    context::{CtxFlags, ClientCtx, ServerCtx, SecurityContext},
    util::Buf
};

fn run() -> Result<(), Error> {
    dbg!("start");
    let name = Name::new(b"nfs/ken-ohki.ryu-oh.org")?;
    dbg!("import name");
    let cname = name.canonicalize()?;
    dbg!("canonicalize name");
    println!("name: {}, cname: {}", name, cname);
    let server_cred = Cred::acquire(Some(&cname), None, CredUsage::Accept)?;
    dbg!("acquired server credentials");
    let client_cred = Cred::acquire(None, None, CredUsage::Initiate)?;
    dbg!("acquired client credentials");
    let client_ctx = ClientCtx::new(&client_cred, &cname, CtxFlags::GSS_C_MUTUAL_FLAG);
    let server_ctx = ServerCtx::new(&server_cred);
    let mut server_tok: Option<Buf> = None;
    loop {
        match client_ctx.step(server_tok.as_ref().map(|b| b.deref()))? {
            None => break,
            Some(client_tok) => match server_ctx.step(&*client_tok)? {
                None => break,
                Some(tok) => { server_tok = Some(tok); }
            }
        }
    }
    dbg!("security context created successfully");
    let secret_msg = client_ctx.wrap(true, b"super secret message")?;
    let decoded_msg = server_ctx.unwrap(&*secret_msg)?;
    println!("the decrypted message is: '{}'", String::from_utf8_lossy(&*decoded_msg));
    Ok(())
}

fn main() {
    match run() {
        Ok(()) => (),
        Err(e) => println!("{}", e),
    }
}
