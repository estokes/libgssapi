use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{OidSet, GSS_MECH_KRB5, GSS_NT_KRB5_PRINCIPAL};

fn main() {
    let desired_mechs = {
        let mut s = OidSet::new().expect("can't create OIDSet");
        s.add(&GSS_MECH_KRB5).expect("can't add GSS_MECH_KRB5");
        s
    };

    let name = Name::new("user@EXAMPLE.ORG".as_ref(), Some(&GSS_NT_KRB5_PRINCIPAL)).expect("can't create name");
    let cred = Cred::pass_acquire(
        Some(&name), "SuperSecret", None, CredUsage::Initiate, Some(&desired_mechs)
    ).expect("can't create credential");

    println!("cred: {:?}", cred);
}