#![allow(dead_code)]
// In-process MIT krb5 KDC fixture for integration tests.
//
// Each TestKdc instance:
// * creates a fresh tempdir for its database, configs, keytabs, and ccache
// * picks a random free port and writes a krb5.conf + kdc.conf that point at it
// * runs `kdb5_util create` and `krb5kdc -n`
// * exposes helpers to add principals, export keytabs, kinit users
// * on Drop, kills the krb5kdc process and the tempdir cleans itself up
//
// Integration tests using this fixture MUST be run with `--test-threads=1`
// because the apply_env() helper sets process-wide env vars (KRB5_CONFIG,
// KRB5_KTNAME, KRB5_CCNAME, KRB5RCACHENAME).

use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub struct TestKdc {
    // Held for its drop side effect (tempdir cleanup).
    _tempdir: tempfile::TempDir,
    kdc: Child,
    pub realm: String,
    pub config_path: PathBuf,
    kdc_conf_path: PathBuf,
    pub keytab_path: PathBuf,
    pub ccache_path: PathBuf,
}

impl TestKdc {
    pub fn new() -> Self {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let dir = tempdir.path().to_path_buf();
        let realm = "EXAMPLE.COM".to_string();
        let port = free_port();

        let kdc_conf_path = dir.join("kdc.conf");
        fs::write(
            &kdc_conf_path,
            format!(
                "[kdcdefaults]\n\
                 \tkdc_ports = {port}\n\
                 \tkdc_tcp_ports = {port}\n\
                 \n\
                 [realms]\n\
                 \t{realm} = {{\n\
                 \t\tdatabase_name = {db}\n\
                 \t\tadmin_keytab = FILE:{admin_kt}\n\
                 \t\tacl_file = {acl}\n\
                 \t\tkey_stash_file = {stash}\n\
                 \t\tmax_life = 1h\n\
                 \t\tmax_renewable_life = 1h\n\
                 \t}}\n",
                port = port,
                realm = realm,
                db = dir.join("principal").display(),
                admin_kt = dir.join("kadm5.keytab").display(),
                acl = dir.join("kadm5.acl").display(),
                stash = dir.join(".k5stash").display(),
            ),
        )
        .expect("write kdc.conf");

        let config_path = dir.join("krb5.conf");
        fs::write(
            &config_path,
            format!(
                "[libdefaults]\n\
                 \tdefault_realm = {realm}\n\
                 \tdns_canonicalize_hostname = false\n\
                 \trdns = false\n\
                 \tforwardable = true\n\
                 \tdns_lookup_kdc = false\n\
                 \tdns_lookup_realm = false\n\
                 \n\
                 [realms]\n\
                 \t{realm} = {{\n\
                 \t\tkdc = 127.0.0.1:{port}\n\
                 \t\tadmin_server = 127.0.0.1\n\
                 \t}}\n\
                 \n\
                 [domain_realm]\n\
                 \ttest.example.com = {realm}\n\
                 \t.example.com = {realm}\n",
                realm = realm,
                port = port,
            ),
        )
        .expect("write krb5.conf");

        fs::write(dir.join("kadm5.acl"), "*/admin@EXAMPLE.COM\t*\n").expect("write acl");

        let env = [
            ("KRB5_CONFIG", config_path.as_os_str()),
            ("KRB5_KDC_PROFILE", kdc_conf_path.as_os_str()),
        ];

        run_assert(
            Command::new("kdb5_util")
                .args(["create", "-s", "-P", "masterpass", "-r", &realm])
                .envs(env.iter().copied()),
            "kdb5_util create",
        );

        let pidfile = dir.join("kdc.pid");
        let mut kdc_cmd = Command::new("krb5kdc");
        kdc_cmd
            .args(["-n", "-P"])
            .arg(&pidfile)
            .args(["-r", &realm])
            .envs(env.iter().copied())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let kdc = kdc_cmd.spawn().expect("spawn krb5kdc");

        wait_for_port(port);

        TestKdc {
            _tempdir: tempdir,
            kdc,
            realm,
            config_path,
            kdc_conf_path,
            keytab_path: dir.join("test.keytab"),
            ccache_path: dir.join("ccache"),
        }
    }

    fn kadmin_env(&self) -> [(&'static str, &Path); 2] {
        [
            ("KRB5_CONFIG", self.config_path.as_path()),
            ("KRB5_KDC_PROFILE", self.kdc_conf_path.as_path()),
        ]
    }

    pub fn add_principal_random_key(&self, principal: &str) {
        run_assert(
            Command::new("kadmin.local")
                .args(["-q", &format!("addprinc -randkey {principal}")])
                .envs(self.kadmin_env().iter().copied()),
            "addprinc -randkey",
        );
    }

    pub fn add_principal_with_password(&self, principal: &str, password: &str) {
        run_assert(
            Command::new("kadmin.local")
                .args(["-q", &format!("addprinc -pw {password} {principal}")])
                .envs(self.kadmin_env().iter().copied()),
            "addprinc -pw",
        );
    }

    pub fn export_keytab(&self, principal: &str) {
        run_assert(
            Command::new("kadmin.local")
                .args([
                    "-q",
                    &format!("ktadd -k {} {principal}", self.keytab_path.display()),
                ])
                .envs(self.kadmin_env().iter().copied()),
            "ktadd",
        );
    }

    pub fn kinit(&self, principal: &str, password: &str) {
        let mut child = Command::new("kinit")
            .args(["-c"])
            .arg(&self.ccache_path)
            .arg(principal)
            .env("KRB5_CONFIG", &self.config_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn kinit");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(password.as_bytes())
            .expect("write kinit stdin");
        let output = child.wait_with_output().expect("wait kinit");
        assert!(
            output.status.success(),
            "kinit failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Set the process-wide env vars so libgssapi sees this KDC's config,
    /// keytab, and ccache. Tests must run single-threaded.
    pub fn apply_env(&self) {
        // SAFETY: tests using this fixture run with --test-threads=1 so no
        // other thread is reading these env vars concurrently.
        unsafe {
            std::env::set_var("KRB5_CONFIG", &self.config_path);
            std::env::set_var(
                "KRB5_KTNAME",
                format!("FILE:{}", self.keytab_path.display()),
            );
            std::env::set_var(
                "KRB5CCNAME",
                format!("FILE:{}", self.ccache_path.display()),
            );
            std::env::set_var("KRB5RCACHENAME", "none:");
        }
    }
}

impl Drop for TestKdc {
    fn drop(&mut self) {
        let _ = self.kdc.kill();
        let _ = self.kdc.wait();
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().unwrap().port()
}

fn wait_for_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("KDC did not start listening on 127.0.0.1:{port} within 5s");
}

fn run_assert(cmd: &mut Command, what: &str) {
    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|e| panic!("spawn {what}: {e}"));
    assert!(
        output.status.success(),
        "{what} failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
