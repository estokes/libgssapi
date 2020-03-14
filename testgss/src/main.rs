use libgssapi::{Name, Cred, CredUsage};

fn run() -> Result<(), Error> {
    dbg!("start");
    let name = Name::new("nfs/ken-ohki.ryu-oh.org")?;
    dbg!("import name");
    let cname = name.canonicalize()?;
    dbg!("canonicalize name");
    let name_s = name.display()?;
    dbg!("display name");
    let cname_s = cname.display()?;
    dbg!("display cname");
    println!(
        "name: {}, cname: {}",
        String::from_utf8_lossy(&name_s),
        String::from_utf8_lossy(&cname_s)
    );
    let cred = Cred::acquire(Some(&cname), None, CredUsage::Accept)?;
    Ok(())
}

fn main() {
    match run() {
        Ok(()) => (),
        Err(e) => println!("{}", e),
    }
}
