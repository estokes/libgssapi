#![allow(dead_code)]
// In-process KDC fixture for integration tests. Works against both MIT
// krb5 and Heimdal — implementation is detected at runtime based on which
// binaries are present.
//
// Each TestKdc instance:
// * creates a fresh tempdir for its database, configs, keytabs, and ccache
// * picks a random free port and writes a combined krb5.conf+kdc config
// * initializes the database and starts the KDC daemon
// * exposes helpers to add principals, export keytabs, kinit users
// * on Drop, kills the KDC process and the tempdir cleans itself up
//
// The apply_env() helper sets process-wide env vars (KRB5_CONFIG,
// KRB5_KTNAME, KRB5CCNAME, KRB5RCACHENAME) and returns a guard over
// TEST_ENV_LOCK; a test holds that guard for its duration. This serializes
// the env-dependent section across tests, so the suite is safe under a
// plain `cargo test` — no `--test-threads=1` required.

use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

// Serializes the process-global Kerberos env (KRB5_CONFIG, KRB5CCNAME, ...)
// that apply_env() writes and that every libgssapi call reads. A test holds
// this guard for its whole body, so the suite is correct under any
// --test-threads value: without it, two concurrent tests would clobber each
// other's env between apply_env() and their GSSAPI calls, and the loser —
// pointed at a ccache with no ticket — would fall back to an interactive
// krb5 password prompt and hang.
static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Impl {
    Mit,
    Heimdal,
}

impl Impl {
    fn detect() -> Self {
        if has_binary("krb5kdc") {
            Impl::Mit
        } else if heimdal_kdc().is_some() || has_binary("kdc") {
            Impl::Heimdal
        } else {
            panic!("no KDC binary found (need MIT krb5kdc or Heimdal kdc)")
        }
    }
}

// The Heimdal KDC daemon isn't on PATH; it lives in an impl-specific spot.
// Debian/Ubuntu put it under /usr/lib/heimdal-servers; macOS ships Heimdal
// inside a private framework.
const HEIMDAL_KDC_PATHS: &[&str] = &[
    "/usr/lib/heimdal-servers/kdc",
    "/System/Library/PrivateFrameworks/Heimdal.framework/Helpers/kdc",
];

fn heimdal_kdc() -> Option<&'static str> {
    HEIMDAL_KDC_PATHS
        .iter()
        .copied()
        .find(|p| Path::new(p).exists())
}

fn has_binary(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub struct TestKdc {
    // Held for its drop side effect (tempdir cleanup).
    _tempdir: tempfile::TempDir,
    kdc: Child,
    imp: Impl,
    pub realm: String,
    pub config_path: PathBuf,
    pub keytab_path: PathBuf,
    pub ccache_path: PathBuf,
}

impl TestKdc {
    pub fn new() -> Self {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let dir = tempdir.path().to_path_buf();
        let realm = "EXAMPLE.COM".to_string();
        let port = free_port();
        let imp = Impl::detect();

        let config_path = dir.join("krb5.conf");
        fs::write(&config_path, build_config(&dir, port, &realm)).expect("write config");
        fs::write(dir.join("acl"), "*/admin@EXAMPLE.COM\t*\n").expect("write acl");

        // Init DB.
        match imp {
            Impl::Mit => run_assert(
                Command::new("kdb5_util")
                    .args(["create", "-s", "-P", "masterpass", "-r", &realm])
                    .env("KRB5_CONFIG", &config_path)
                    .env("KRB5_KDC_PROFILE", &config_path),
                "kdb5_util create",
            ),
            Impl::Heimdal => run_assert(
                Command::new("kadmin")
                    .arg("-c")
                    .arg(&config_path)
                    .args([
                        "-l",
                        "init",
                        "--realm-max-ticket-life=1h",
                        "--realm-max-renewable-life=1h",
                        &realm,
                    ]),
                "kadmin init",
            ),
        }

        // Start KDC.
        let kdc = match imp {
            Impl::Mit => Command::new("krb5kdc")
                .args(["-n", "-P"])
                .arg(dir.join("kdc.pid"))
                .args(["-r", &realm])
                .env("KRB5_CONFIG", &config_path)
                .env("KRB5_KDC_PROFILE", &config_path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn krb5kdc"),
            Impl::Heimdal => {
                let mut cmd = Command::new(heimdal_kdc().unwrap_or("kdc"));
                cmd.arg("-c")
                    .arg(&config_path)
                    .arg("--addresses=127.0.0.1")
                    .arg(format!("--ports={port}/tcp {port}/udp"));
                if cfg!(target_os = "macos") {
                    // macOS ships the KDC as a launchd helper that gets its
                    // listening sockets and sandbox from launchd. Run standalone
                    // it binds nothing and exits unless told to listen on the
                    // network itself and to skip the sandbox.
                    cmd.arg("--listen-on-network").arg("--no-sandbox");
                }
                cmd.stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn heimdal kdc")
            }
        };

        wait_for_port(port);

        TestKdc {
            _tempdir: tempdir,
            kdc,
            imp,
            realm,
            config_path,
            keytab_path: dir.join("test.keytab"),
            ccache_path: dir.join("ccache"),
        }
    }

    fn kadmin_local(&self) -> Command {
        match self.imp {
            Impl::Mit => {
                let mut c = Command::new("kadmin.local");
                c.env("KRB5_CONFIG", &self.config_path)
                    .env("KRB5_KDC_PROFILE", &self.config_path);
                c
            }
            Impl::Heimdal => {
                let mut c = Command::new("kadmin");
                c.arg("-c").arg(&self.config_path).arg("-l");
                c
            }
        }
    }

    pub fn add_principal_random_key(&self, principal: &str) {
        let mut cmd = self.kadmin_local();
        match self.imp {
            Impl::Mit => {
                cmd.args(["-q", &format!("addprinc -randkey {principal}")]);
            }
            Impl::Heimdal => {
                cmd.args(["add", "--use-defaults", "--random-key", principal]);
            }
        }
        run_assert(&mut cmd, "add_principal_random_key");
    }

    pub fn add_principal_with_password(&self, principal: &str, password: &str) {
        let mut cmd = self.kadmin_local();
        match self.imp {
            Impl::Mit => {
                cmd.args(["-q", &format!("addprinc -pw {password} {principal}")]);
            }
            Impl::Heimdal => {
                cmd.args([
                    "add",
                    "--use-defaults",
                    &format!("--password={password}"),
                    principal,
                ]);
            }
        }
        run_assert(&mut cmd, "add_principal_with_password");
    }

    pub fn export_keytab(&self, principal: &str) {
        let mut cmd = self.kadmin_local();
        let kt = self.keytab_path.to_string_lossy().into_owned();
        match self.imp {
            Impl::Mit => {
                cmd.args(["-q", &format!("ktadd -k {kt} {principal}")]);
            }
            Impl::Heimdal => {
                cmd.args(["ext_keytab", "-k", &kt, principal]);
            }
        }
        run_assert(&mut cmd, "export_keytab");
    }

    pub fn kinit(&self, principal: &str, password: &str) {
        let mut cmd = Command::new("kinit");
        cmd.arg("-c")
            .arg(&self.ccache_path)
            .arg(principal)
            .env("KRB5_CONFIG", &self.config_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        // kinit reads the password from the controlling terminal (/dev/tty),
        // not stdin, whenever one is present — so the piped password below is
        // ignored under an interactive `cargo test` and kinit blocks on a
        // secure-input prompt. setsid(2) puts the child in a new session with
        // no controlling terminal, so it has no tty to prompt on and reads
        // the password from stdin instead (the same path that works in CI).
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().expect("spawn kinit");
        // Heimdal's kinit still prints a prompt to stderr before reading
        // stdin; that's harmless. Both impls accept the password on stdin
        // followed by a newline.
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(password.as_bytes()).expect("write kinit stdin");
        stdin.write_all(b"\n").expect("write kinit newline");
        let output = child.wait_with_output().expect("wait kinit");
        assert!(
            output.status.success(),
            "kinit failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Set the process-wide env vars so libgssapi sees this KDC's config,
    /// keytab, and ccache, and return a guard serializing this against other
    /// tests. Hold the guard for the rest of the test: the env stays valid
    /// only until another test takes the lock and points it at its own KDC.
    #[must_use = "hold the returned guard for the duration of the test; \
                  dropping it immediately releases the env lock and lets \
                  another test clobber KRB5CCNAME/KRB5_CONFIG"]
    pub fn apply_env(&self) -> MutexGuard<'static, ()> {
        // A panic in a prior test poisons the lock, but the guarded data is
        // just () — nothing to corrupt — so recover and carry on.
        let guard = TEST_ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        // SAFETY: we hold TEST_ENV_LOCK, so no other test thread is reading
        // or writing these env vars concurrently.
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
        guard
    }
}

impl Drop for TestKdc {
    fn drop(&mut self) {
        let _ = self.kdc.kill();
        let _ = self.kdc.wait();
    }
}

fn build_config(dir: &Path, port: u16, realm: &str) -> String {
    // One config file used by both impls. MIT ignores `[kdc]`; Heimdal
    // ignores `[kdcdefaults]` and the database-related keys inside
    // `[realms]`.
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
         \t\tdatabase_name = {db}\n\
         \t\tadmin_keytab = FILE:{admin_kt}\n\
         \t\tacl_file = {acl}\n\
         \t\tkey_stash_file = {stash}\n\
         \t\tmax_life = 1h\n\
         \t\tmax_renewable_life = 1h\n\
         \t}}\n\
         \n\
         [kdcdefaults]\n\
         \tkdc_ports = {port}\n\
         \tkdc_tcp_ports = {port}\n\
         \n\
         [domain_realm]\n\
         \ttest.example.com = {realm}\n\
         \t.example.com = {realm}\n\
         \n\
         [kdc]\n\
         \tdatabase = {{\n\
         \t\tdbname = {heimdal_db}\n\
         \t\tacl_file = {acl}\n\
         \t\tmkey_file = {heimdal_mkey}\n\
         \t\tlog_file = {heimdal_log}\n\
         \t}}\n",
        db = dir.join("principal").display(),
        admin_kt = dir.join("kadm5.keytab").display(),
        acl = dir.join("acl").display(),
        stash = dir.join(".k5stash").display(),
        heimdal_db = dir.join("heimdal").display(),
        heimdal_mkey = dir.join("heimdal.mkey").display(),
        heimdal_log = dir.join("heimdal.log").display(),
    )
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

