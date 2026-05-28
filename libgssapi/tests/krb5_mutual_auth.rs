//! Integration test: mutual auth handshake + wrap/unwrap roundtrip against
//! a real (in-process) MIT krb5 KDC. Must run with `--test-threads=1`
//! because the fixture sets process-wide env vars.

mod common;

use common::TestKdc;

use libgssapi::context::{ClientCtx, CtxFlags, SecurityContext, ServerCtx};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{GSS_MECH_KRB5, GSS_NT_HOSTBASED_SERVICE, OidSet};
use libgssapi::util::Buf;

#[test]
fn mutual_auth_handshake_and_wrap() {
    let kdc = TestKdc::new();
    kdc.add_principal_with_password("testuser", "testpass");
    kdc.add_principal_random_key("nfs/test.example.com");
    kdc.export_keytab("nfs/test.example.com");
    kdc.kinit("testuser", "testpass");
    kdc.apply_env();

    let mut desired_mechs = OidSet::new();
    desired_mechs.add(GSS_MECH_KRB5).unwrap();

    let target = Name::new(b"nfs@test.example.com", Some(GSS_NT_HOSTBASED_SERVICE)).unwrap();
    let cname = target.canonicalize(Some(GSS_MECH_KRB5)).unwrap();

    let server_cred = Cred::acquire(
        Some(&cname),
        None,
        CredUsage::Accept,
        Some(&desired_mechs),
    )
    .unwrap_or_else(|e| panic!("acquire server cred: {e}"));
    let mut server_ctx = ServerCtx::new(Some(server_cred));

    let client_cred = Cred::acquire(None, None, CredUsage::Initiate, Some(&desired_mechs))
        .expect("acquire client cred");
    let mut client_ctx = ClientCtx::new(
        Some(client_cred),
        cname,
        CtxFlags::GSS_C_MUTUAL_FLAG,
        Some(GSS_MECH_KRB5),
    );

    let mut server_tok: Option<Buf> = None;
    let mut steps = 0;
    loop {
        steps += 1;
        assert!(steps < 10, "handshake did not converge");
        let client_out = client_ctx
            .step(server_tok.as_ref().map(|b| &**b), None)
            .unwrap_or_else(|e| panic!("client step {steps}: {e}"));
        match client_out {
            None => break,
            Some(client_tok) => {
                let server_out = server_ctx
                    .step(&client_tok)
                    .unwrap_or_else(|e| panic!("server step {steps}: {e}"));
                match server_out {
                    None => break,
                    Some(tok) => server_tok = Some(tok),
                }
            }
        }
    }

    assert!(client_ctx.is_complete());
    assert!(server_ctx.is_complete());

    let secret = b"super secret message";
    let wrapped = client_ctx.wrap(true, secret).expect("wrap");
    let unwrapped = server_ctx.unwrap(&wrapped).expect("unwrap");
    assert_eq!(&*unwrapped, secret);

    // Round-trip in the other direction too.
    let reply = b"and a reply";
    let wrapped = server_ctx.wrap(true, reply).expect("server wrap");
    let unwrapped = client_ctx.unwrap(&wrapped).expect("client unwrap");
    assert_eq!(&*unwrapped, reply);
}
