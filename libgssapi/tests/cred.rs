//! Credential acquisition and storage tests against an in-process KDC.
//! `apply_env()` returns a guard that serializes the process-wide env it
//! sets, so these run safely under a plain `cargo test`.

mod common;

use common::TestKdc;

use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{GSS_MECH_KRB5, GSS_NT_USER_NAME};

#[test]
fn acquire_initiate_cred() {
    let kdc = TestKdc::new();
    kdc.add_principal_with_password("testuser", "testpass");
    kdc.kinit("testuser", "testpass");
    let _env = kdc.apply_env();

    // Acquire by explicit name rather than None. A None (default) initiator
    // name makes Apple's GSS.framework enumerate credential *identities* —
    // including PKINIT — which probes the keychain for client certificates
    // and, in an interactive session, raises a secure-input prompt that
    // hangs the test. Naming the principal sends Heimdal straight to that
    // principal's ccache, skipping the identity/PKINIT search entirely.
    let name = Name::new(b"testuser", Some(GSS_NT_USER_NAME))
        .expect("create name")
        .canonicalize(Some(GSS_MECH_KRB5))
        .expect("canonicalize name");
    let cred = Cred::acquire(Some(&name), None, CredUsage::Initiate, None)
        .unwrap_or_else(|e| panic!("acquire: {e}"));
    let info = cred.info().expect("cred info");
    assert!(
        format!("{}", info.name).starts_with("testuser@"),
        "expected testuser principal, got {}",
        info.name
    );
}

#[cfg(feature = "store")]
#[test]
fn store_returns_real_elements_and_usage() {
    use libgssapi::oid::{GSS_MECH_KRB5, OidSet};
    // Pre-fix, gss_store_cred's outputs were written into stack temporaries,
    // so the returned OidSet was always empty and the returned CredUsage
    // was always `Both`. This test would have failed under that bug.
    let kdc = TestKdc::new();
    kdc.add_principal_with_password("testuser", "testpass");
    kdc.kinit("testuser", "testpass");
    let _env = kdc.apply_env();

    let desired_mechs = OidSet::singleton(GSS_MECH_KRB5).unwrap();

    let cred = Cred::acquire(None, None, CredUsage::Initiate, Some(&desired_mechs))
        .expect("acquire cred");

    let (elements_stored, usage_stored) = cred
        .store(true, true, CredUsage::Initiate, Some(GSS_MECH_KRB5))
        .unwrap_or_else(|e| panic!("store: {e}"));

    assert!(
        elements_stored.len() > 0,
        "elements_stored should be non-empty after a successful store"
    );
    assert!(
        elements_stored.contains(GSS_MECH_KRB5).unwrap(),
        "elements_stored should contain GSS_MECH_KRB5"
    );

    // gssapi can promote the requested usage; Initiate or Both are
    // acceptable. The assertion here is mostly checking that *some* value
    // propagates back — pre-fix this was always `Both`.
    match usage_stored {
        CredUsage::Initiate | CredUsage::Both => {}
        CredUsage::Accept => panic!("unexpected usage_stored: Accept"),
    }
}
