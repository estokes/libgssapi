use std::borrow::Borrow;
use libgssapi::{Name, Cred, CredUsage, Error, ClientCtx, ServerCtx, CtxFlags, Buf};

fn run() -> Result<(), Error> {
    dbg!("start");
    let name = Name::new(b"nfs/ken-ohki.ryu-oh.org")?;
    dbg!("import name");
    let cname = name.canonicalize()?;
    dbg!("canonicalize name");
    let name_s = name.display()?;
    dbg!("display name");
    let cname_s = cname.display()?;
    dbg!("display cname");
    println!(
        "name: {}, cname: {}",
        String::from_utf8_lossy(name_s.borrow()),
        String::from_utf8_lossy(cname_s.borrow())
    );
    let server_cred = Cred::acquire(Some(&cname), None, CredUsage::Accept)?;
    dbg!("acquired server credentials");
    let client_cred = Cred::acquire(None, None, CredUsage::Initiate)?;
    dbg!("acquired client credentials");
    let client_ctx = ClientCtx::new(&client_cred, &cname, CtxFlags::GSS_C_MUTUAL_FLAG);
    let server_ctx = ServerCtx::new(&server_cred);
    let mut server_tok: Option<Buf> = None;
    loop {
        match client_ctx.step(server_tok.as_ref().map(|b| b.borrow()))? {
            Some(client_tok) => { server_tok = server_ctx.step(client_tok.borrow())?; }
            None => break
        }
    }
    dbg!("security context created successfully");
    Ok(())
}

fn main() {
    match run() {
        Ok(()) => (),
        Err(e) => println!("{}", e),
    }
}
