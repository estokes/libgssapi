/*
An example program demonstrating mutual authentication and encryption
between a server and a client using the Kerberos v5 gssapi mech. In
order to run this example you must have a working kerberos
environment, more specifically,

* a valid krb5.conf
* a working KDC for your realm
* a service principal for the server e.g. nfs/server.example.com@EXAMPLE.COM
* a keytab containing the service principal's key and that is readable by the user 
  you want to run the example as. e.g. if not running as root set the environment 
  variable KRB5_KTNAME=FILE:/path/to/keytab
* a valid TGT from your KDC e.g. klist should print at least something like,

Ticket cache: FILE:/tmp/krb5cc_1000_Ooxj5E
Default principal: user@EXAMPLE.COM

Valid starting       Expires              Service principal
03/17/2020 18:10:05  03/18/2020 04:10:05  krbtgt/EXAMPLE.COM@EXAMPLE.COM
	renew until 03/18/2020 18:10:05

if it doesn't then you need to run kinit to renew your TGT.

a successful run will look like,

KRB5_KTNAME=FILE:/path/to/krb5.keytab cargo run --example krb5 nfs@host.example.com
import name
canonicalize name for kerberos 5
server name: nfs@host.example.com, server cname: nfs/host.example.com@
acquired server credentials
acquired default client credentials
security context initialized successfully
client ctx info: CtxInfo {
    source_name: user@EXAMPLE.COM,
    target_name: nfs/host.example.com@,
    lifetime: 35923,
    mechanism: GSS_MECH_KRB5,
    flags: GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG | GSS_C_TRANS_FLAG,
    local: true,
    open: true,
}
server ctx info: CtxInfo {
    source_name: user@EXAMPLE.COM,
    target_name: nfs/host.example.com@EXAMPLE.COM,
    lifetime: 36223,
    mechanism: GSS_MECH_KRB5,
    flags: GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG | GSS_C_PROT_READY_FLAG | GSS_C_TRANS_FLAG,
    local: false,
    open: true,
}
the decrypted message is: 'super secret message'

Depending on which implementation of gssapi you have the error
messages it produces may not be very helpful (well, probably none of
them actually produce helpful error messages). For example, if you
can't read the services' keytab this is what MIT Kerberos will produce,

KRB5_KTNAME=FILE:/path/to/unreadable/krb5.keytab cargo run --example krb5 nfs@host.example.com
import name
canonicalize name for kerberos 5
server name: nfs@host.example.com, server cname: nfs/host.example.com@
gssapi major error Unspecified GSS failure.  Minor code may provide more information
gssapi minor error The routine must be called again to complete its function
gssapi minor error The token's validity period has expired
gssapi minor error A later token has already been processed

Yep, that's pretty helpful. Thanks gssapi!

When using MIT Kerberos you can get some better info by setting
KRB5_TRACE=/dev/stderr (or whatever file you want the trace written
to). I'm sure a similar thing exists for Heimdal, but I don't know what
it is.

*/

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
