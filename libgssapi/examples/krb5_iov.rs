/* This is exactly the same as the krb5 example (see the top of that
 * program for a detailed description of how to run it and what you
 * should see when you do run it), however it demonstrates using
 * wrap_iov, and unwrap_iov to do in place encryption/decryption. */

use bytes::BytesMut;
use libgssapi::{
    context::{ClientCtx, CtxFlags, SecurityContext, ServerCtx},
    credential::{Cred, CredUsage},
    error::Error,
    name::Name,
    oid::{OidSet, GSS_MECH_KRB5, GSS_NT_HOSTBASED_SERVICE},
    util::{Buf, GssIov, GssIovFake, GssIovType},
};
use std::env::args;

fn setup_server_ctx(
    service_name: &[u8],
    desired_mechs: &OidSet,
) -> Result<(ServerCtx, Name), Error> {
    println!("import name");
    let name = Name::new(service_name, Some(&GSS_NT_HOSTBASED_SERVICE))?;
    let cname = name.canonicalize(Some(&GSS_MECH_KRB5))?;
    println!("canonicalize name for kerberos 5");
    println!("server name: {}, server cname: {}", name, cname);
    let server_cred =
        Cred::acquire(Some(&cname), None, CredUsage::Accept, Some(desired_mechs))?;
    println!("acquired server credentials: {:#?}", server_cred.info()?);
    Ok((ServerCtx::new(server_cred), cname))
}

fn setup_client_ctx(
    service_name: Name,
    desired_mechs: &OidSet,
) -> Result<ClientCtx, Error> {
    let client_cred =
        Cred::acquire(None, None, CredUsage::Initiate, Some(&desired_mechs))?;
    println!(
        "acquired default client credentials: {:#?}",
        client_cred.info()?
    );
    Ok(ClientCtx::new(
        client_cred,
        service_name,
        CtxFlags::GSS_C_MUTUAL_FLAG,
        Some(&GSS_MECH_KRB5),
    ))
}

// This wraps a secret message asking gssapi to allocate the header
// padding and trailer, but it encrypts the actual message content in
// place. This is easy mode for iovs, and if your messages are large
// it's probably nearly as fast as hard mode.
fn wrap_secret_msg_alloc(ctx: &mut ClientCtx) -> Result<BytesMut, Error> {
    let mut buf = BytesMut::new();
    let mut data = {
        buf.extend_from_slice(b"super secret message");
        buf.split()
    };
    let mut iovs = [
        // iovs we want gssapi to allocate must be created with
        // new_alloc, such iovs will be freed with gss_release_buffer
        // when they are dropped.
        GssIov::new_alloc(GssIovType::Header),
        GssIov::new(GssIovType::Data, &mut *data),
        GssIov::new_alloc(GssIovType::Padding),
        GssIov::new_alloc(GssIovType::Trailer),
    ];
    ctx.wrap_iov(true, &mut iovs[..])?;
    println!("buffer lengths are as follows ...");
    println!("header:  {}", iovs[0].len());
    println!("data:    {}", iovs[1].len());
    println!("padding: {}", iovs[2].len());
    println!("trailer: {}", iovs[3].len());

    // now we would normally use a function like `write_vectored` to
    // write our iovecs to a socket. We'll simulate that by assembling
    // it all in a BytesMut that we will then pass to the decrypt
    // function.
    buf.extend_from_slice(&*iovs[0]);
    buf.extend_from_slice(&*iovs[1]);
    buf.extend_from_slice(&*iovs[2]);
    buf.extend_from_slice(&*iovs[3]);
    // of course we would not do the above in a real application
    // because it copies all the data we just carefully and verbosely
    // used wrap_iov to avoid copying! But this is an example,
    Ok(buf.split())
}

// This wraps a secret message without asking gssapi to allocate
// anything ever, it is quite verbose, but potentially a LOT faster
// than standard wrap
fn wrap_secret_msg_noalloc(ctx: &mut ClientCtx) -> Result<BytesMut, Error> {
    let mut buf = BytesMut::new();
    let mut data = {
        buf.extend_from_slice(b"super secret message");
        buf.split()
    };
    // step 1, we need to ask gssapi for the length of all the buffers
    // that make up a token. We do this by passing "fake" buffers for
    // the header, paddding, and trailer, along with the real data
    // buffer.
    let mut len_iovs = [
        GssIovFake::new(GssIovType::Header),
        GssIov::new(GssIovType::Data, &mut *data).as_fake(),
        GssIovFake::new(GssIovType::Padding),
        GssIovFake::new(GssIovType::Trailer),
    ];
    ctx.wrap_iov_length(true, &mut len_iovs[..])?;

    println!("requested buffer lengths are as follows ...");
    println!("header:  {}", len_iovs[0].len());
    println!("data:    {}", len_iovs[1].len());
    println!("padding: {}", len_iovs[2].len());
    println!("trailer: {}", len_iovs[3].len());

    // step 2, now that we know what length each buffer must be, we
    // carve out a chunk of the buffer for each part. the Bytes
    // library makes this much easier on us.
    let mut header = {
        buf.resize(len_iovs[0].len(), 0x0);
        buf.split()
    };
    let mut padding = {
        buf.resize(len_iovs[2].len(), 0x0);
        buf.split()
    };
    let mut trailer = {
        buf.resize(len_iovs[3].len(), 0x0);
        buf.split()
    };
    {
        let mut iovs = [
            GssIov::new(GssIovType::Header, &mut *header),
            GssIov::new(GssIovType::Data, &mut *data),
            GssIov::new(GssIovType::Padding, &mut *padding),
            GssIov::new(GssIovType::Trailer, &mut *trailer),
        ];
        // and we can ask gssapi to encrypt/encode the buffers
        ctx.wrap_iov(true, &mut iovs[..])?;
    }

    // now we would normally use a function like `write_vectored` to
    // write our iovecs to a socket. We'll simulate that by assembling
    // it all in a BytesMut that we will then pass to the decrypt
    // function.
    buf.extend_from_slice(&*header);
    buf.extend_from_slice(&*data);
    buf.extend_from_slice(&*padding);
    buf.extend_from_slice(&*trailer);
    // of course we would not do the above in a real application
    // because it copies all the data we just carefully and verbosely
    // used wrap_iov to avoid copying! But this is an example,
    Ok(buf.split())
}

fn unwrap_secret_msg(ctx: &mut ServerCtx, mut msg: BytesMut) -> Result<BytesMut, Error> {
    let (hdr_len, data_len) = {
        let mut iov = [
            // this is the entire token
            GssIov::new(GssIovType::Stream, &mut *msg),
            // in the end this will point into the above buffer
            GssIov::new(GssIovType::Data, &mut []),
        ];
        ctx.unwrap_iov(&mut iov[..])?;
        let hdr_len = iov[0].header_length(&iov[1]).unwrap();
        let data_len = iov[1].len();
        (hdr_len, data_len)
    };
    let mut data = msg.split_off(hdr_len);
    msg.clear(); // delete the header
    data.truncate(data_len); // delete the trailer
    Ok(data)
}

fn run(service_name: &[u8]) -> Result<(), Error> {
    let desired_mechs = {
        let mut s = OidSet::new()?;
        s.add(&GSS_MECH_KRB5)?;
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
                Some(tok) => {
                    server_tok = Some(tok);
                }
            },
        }
    }
    println!("security context initialized successfully");
    println!("client ctx info: {:#?}", client_ctx.info()?);
    println!("server ctx info: {:#?}", server_ctx.info()?);
    println!("wrapping secret message using no alloc method");
    let encrypted = wrap_secret_msg_noalloc(&mut client_ctx)?;
    let decrypted = unwrap_secret_msg(&mut server_ctx, encrypted)?;
    println!(
        "The secret message is \"{}\"",
        String::from_utf8_lossy(&*decrypted)
    );
    println!("wrapping secret message using alloc method");
    let encrypted = wrap_secret_msg_alloc(&mut client_ctx)?;
    let decrypted = unwrap_secret_msg(&mut server_ctx, encrypted)?;
    println!(
        "The secret message is \"{}\"",
        String::from_utf8_lossy(&*decrypted)
    );
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
