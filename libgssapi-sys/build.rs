use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const APPLE_FRAMEWORKS: &str =
    "-F/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks";

#[derive(Clone, Copy)]
enum Gssapi {
    Mit,
    Heimdal,
    Apple,
}

fn emit_link_line(imp: &Gssapi) {
    match imp {
        Gssapi::Mit => println!("cargo:rustc-link-lib=gssapi_krb5"),
        Gssapi::Heimdal => println!("cargo:rustc-link-lib=gssapi"),
        Gssapi::Apple => println!("cargo:rustc-link-lib=framework=GSS"),
    }
}

/// Install prefixes from `LIBGSSAPI_PREFIX` (colon-separated). Each prefix
/// contributes `<prefix>/include` to bindgen and `<prefix>/lib` to the
/// linker and the library search below.
fn user_prefixes() -> Vec<PathBuf> {
    match env::var("LIBGSSAPI_PREFIX") {
        Err(_) => Vec::new(),
        Ok(s) => s
            .split(':')
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .collect(),
    }
}

fn krb5_config_prefix() -> Option<PathBuf> {
    Command::new("krb5-config")
        .arg("gssapi")
        .arg("--prefix")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| PathBuf::from(s.trim()))
        .filter(|p| !p.as_os_str().is_empty())
}

/// Non-recursive check for a `lib<stem>.so*` in `dir`. `stem` is matched
/// exactly so that `libgssapi` does not also match `libgssapi_krb5` (the
/// remainder after the stem must begin with `.so`).
fn dir_has_lib(dir: &Path, stem: &str) -> bool {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return false,
    };
    entries.flatten().any(|entry| {
        match entry.file_name().to_string_lossy().strip_prefix(stem) {
            Some(rest) => rest.starts_with(".so"),
            None => false,
        }
    })
}

fn builder_from_pkgconfig(lib: pkg_config::Library) -> bindgen::Builder {
    bindgen::Builder::default().clang_args(
        lib.include_paths
            .iter()
            .map(|path| format!("-I{}", path.to_string_lossy())),
    )
}

/// Builder for the cases where pkg-config didn't supply include paths
/// (library search, cross compile, or a forced impl with no `.pc`). Adds
/// `<prefix>/include` for each `LIBGSSAPI_PREFIX` entry, forwards Nix's
/// cflags so headers in the Nix store are found, and the macOS framework
/// search path for the Apple GSS framework.
fn searched_builder(imp: &Gssapi) -> bindgen::Builder {
    let builder = bindgen::Builder::default();
    match imp {
        Gssapi::Mit | Gssapi::Heimdal => {
            let builder = user_prefixes().iter().fold(builder, |b, p| {
                b.clang_arg(format!("-I{}", p.join("include").display()))
            });
            match env::var("NIX_CFLAGS_COMPILE") {
                Err(_) => builder,
                Ok(flags) => builder.clang_args(flags.split(" ")),
            }
        }
        Gssapi::Apple => builder.clang_arg(APPLE_FRAMEWORKS),
    }
}

fn emit_user_prefix_link_search() {
    for p in user_prefixes() {
        println!("cargo:rustc-link-search=native={}", p.join("lib").display());
    }
}

fn try_pkgconfig() -> Result<(Gssapi, bindgen::Builder), pkg_config::Error> {
    match pkg_config::probe_library("mit-krb5-gssapi") {
        Ok(lib) => Ok((Gssapi::Mit, builder_from_pkgconfig(lib))),
        Err(_) => match pkg_config::probe_library("heimdal-gssapi") {
            Ok(lib) => Ok((Gssapi::Heimdal, builder_from_pkgconfig(lib))),
            Err(lib) => Err(lib),
        },
    }
}

/// `LIBGSSAPI_IMPL` forces the implementation, overriding autodetection.
/// Useful on machines that have both MIT and Heimdal installed, where the
/// probe order would otherwise decide for you.
fn forced_impl() -> Option<Gssapi> {
    let val = env::var("LIBGSSAPI_IMPL").ok()?;
    match val.trim().to_ascii_lowercase().as_str() {
        "" => None,
        "mit" => Some(Gssapi::Mit),
        "heimdal" => Some(Gssapi::Heimdal),
        "apple" => Some(Gssapi::Apple),
        other => panic!(
            "LIBGSSAPI_IMPL must be one of \"mit\", \"heimdal\", \"apple\"; got {:?}",
            other
        ),
    }
}

/// Select a forced impl. Prefer that impl's pkg-config (for include paths
/// and the link directives it emits); fall back to emitting the link line
/// ourselves with a bare/prefix/Nix/framework builder when pkg-config can't
/// be used (cross compile, or no `.pc` for the chosen impl).
fn select_forced(imp: Gssapi, cross_compile: bool) -> (Gssapi, bindgen::Builder) {
    let pc = match imp {
        Gssapi::Mit => Some("mit-krb5-gssapi"),
        Gssapi::Heimdal => Some("heimdal-gssapi"),
        Gssapi::Apple => None,
    };
    if !cross_compile {
        if let Some(pc) = pc {
            if let Ok(lib) = pkg_config::probe_library(pc) {
                return (imp, builder_from_pkgconfig(lib));
            }
        }
    }
    emit_link_line(&imp);
    emit_user_prefix_link_search();
    (imp, searched_builder(&imp))
}

/// Autodetect MIT vs Heimdal by looking for the library, when pkg-config is
/// unavailable. Searches `<prefix>/lib` for each `LIBGSSAPI_PREFIX` entry,
/// the `krb5-config --prefix` lib dir, `LD_LIBRARY_PATH`, and the usual
/// system lib dirs (non-recursively). When a match is found its directory
/// is added to the linker search path.
fn which() -> Gssapi {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_family = env::var("CARGO_CFG_TARGET_FAMILY").unwrap();

    if target_os == "macos" {
        emit_link_line(&Gssapi::Apple);
        return Gssapi::Apple;
    } else if target_os == "windows" {
        panic!("use SSPI on windows")
    } else if target_family != "unix" {
        panic!("libgssapi isn't ported to this platform yet")
    }

    emit_user_prefix_link_search();
    let mut lib_dirs: Vec<PathBuf> = Vec::new();
    for p in user_prefixes() {
        lib_dirs.push(p.join("lib"));
    }
    if let Some(p) = krb5_config_prefix() {
        lib_dirs.push(p.join("lib"));
    }
    if let Ok(ldpath) = env::var("LD_LIBRARY_PATH") {
        lib_dirs.extend(ldpath.split(':').filter(|d| !d.is_empty()).map(PathBuf::from));
    }
    lib_dirs.extend(["/lib", "/lib64", "/usr/lib", "/usr/lib64"].map(PathBuf::from));

    for dir in &lib_dirs {
        if dir_has_lib(dir, "libgssapi_krb5") {
            println!("cargo:rustc-link-search=native={}", dir.display());
            emit_link_line(&Gssapi::Mit);
            return Gssapi::Mit;
        }
        if dir_has_lib(dir, "libgssapi") {
            println!("cargo:rustc-link-search=native={}", dir.display());
            emit_link_line(&Gssapi::Heimdal);
            return Gssapi::Heimdal;
        }
    }
    panic!(
        "no MIT or Heimdal gssapi library found. Set LIBGSSAPI_IMPL (\"mit\" or \
         \"heimdal\") to pick an implementation, and/or LIBGSSAPI_PREFIX to the \
         install prefix(es) to search, colon-separated - headers are expected \
         under <prefix>/include and libraries under <prefix>/lib."
    );
}

fn main() {
    // Emitting any rerun-if instruction disables Cargo's default
    // whole-package change detection, so we must name every input here.
    println!("cargo:rerun-if-env-changed=LIBGSSAPI_IMPL");
    println!("cargo:rerun-if-env-changed=LIBGSSAPI_PREFIX");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/consts.h");
    println!("cargo:rerun-if-changed=src/wrapper_mit.h");
    println!("cargo:rerun-if-changed=src/wrapper_heimdal.h");
    println!("cargo:rerun-if-changed=src/wrapper_apple.h");

    let cross_compile = env::var("HOST").unwrap() != env::var("TARGET").unwrap();

    let (imp, builder) = match forced_impl() {
        Some(imp) => select_forced(imp, cross_compile),
        None => match (cross_compile, try_pkgconfig()) {
            (false, Ok((imp, builder))) => (imp, builder),
            _ => {
                let imp = which();
                (imp, searched_builder(&imp))
            }
        },
    };
    let bindings = builder
        .allowlist_type("(OM_.+|gss_.+)")
        .allowlist_var("_?GSS_.+|gss_.+")
        .allowlist_function("gss_.*")
        .header(match imp {
            Gssapi::Mit => "src/wrapper_mit.h",
            Gssapi::Heimdal => "src/wrapper_heimdal.h",
            Gssapi::Apple => "src/wrapper_apple.h",
        })
        .generate()
        .expect("failed to generate gssapi bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("failed to write bindings")
}
