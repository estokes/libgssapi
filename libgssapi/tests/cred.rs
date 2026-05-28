//! Credential acquisition and storage tests against an in-process KDC.
//! Must run with `--test-threads=1` (TestKdc sets process-wide env vars).

mod common;

use common::TestKdc;

use libgssapi::credential::{Cred, CredUsage};

#[test]
fn acquire_default_initiate_cred() {
    let kdc = TestKdc::new();
    kdc.add_principal_with_password("testuser", "testpass");
    kdc.kinit("testuser", "testpass");
    kdc.apply_env();

    let cred = Cred::acquire(None, None, CredUsage::Initiate, None)
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
    kdc.apply_env();

    let mut desired_mechs = OidSet::new();
    desired_mechs.add(&GSS_MECH_KRB5).unwrap();

    let cred = Cred::acquire(None, None, CredUsage::Initiate, Some(&desired_mechs))
        .expect("acquire cred");

    let (elements_stored, usage_stored) = cred
        .store(true, true, CredUsage::Initiate, Some(&GSS_MECH_KRB5))
        .unwrap_or_else(|e| panic!("store: {e}"));

    assert!(
        elements_stored.len() > 0,
        "elements_stored should be non-empty after a successful store"
    );
    assert!(
        elements_stored.contains(&GSS_MECH_KRB5).unwrap(),
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
