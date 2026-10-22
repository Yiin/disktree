//! The Windows icon, and the remote agents `cargo xtask agent` built.

use std::path::{Path, PathBuf};

include!("../disktree-agent/source_id.rs");

/// The architectures `cargo xtask agent` builds, as `uname -m` names them.
const AGENTS: [&str; 2] = ["aarch64", "x86_64"];

/// Embed each agent in `target/agent` that is there, and say which through
/// `cfg(agent_<arch>)` and `DISKTREE_AGENT_<ARCH>`. Without any the app
/// still builds; connecting to another machine then says to build them.
fn embed_agents() {
    let manifest =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let dir = manifest.join("../../target/agent");
    // Watched as a directory, which cargo scans for changes: a path that
    // does not exist would rerun this script, and rebuild the app, on every
    // build. So the folder is made if it is missing.
    let _ = std::fs::create_dir_all(&dir);
    println!("cargo:rerun-if-changed={}", dir.display());
    warn_if_stale(&manifest.join("../.."), &dir);
    for arch in AGENTS {
        println!("cargo:rustc-check-cfg=cfg(agent_{arch})");
        let agent: &Path = &dir.join(format!("disktree-agent-{arch}"));
        if agent.is_file() {
            println!("cargo:rustc-cfg=agent_{arch}");
            println!(
                "cargo:rustc-env=DISKTREE_AGENT_{}={}",
                arch.to_uppercase(),
                agent.display()
            );
        }
    }
}

/// Warn when the agents in `dir` were built from other sources than the
/// ones here: connecting with one would be refused, and `make agent`
/// fixes it now. Agents with no record are left to that refusal too.
fn warn_if_stale(root: &Path, dir: &Path) {
    for source in AGENT_SOURCES {
        println!("cargo:rerun-if-changed={}", root.join(source).display());
    }
    let built = std::fs::read_to_string(dir.join("build-id"));
    let current = agent_source_id(root);
    let any = AGENTS
        .iter()
        .any(|arch| dir.join(format!("disktree-agent-{arch}")).is_file());
    if any && built.ok().as_deref().map(str::trim) != Some(current.as_str()) {
        println!(
            "cargo:warning=the agents in target/agent were built from other \
             sources than these ({current}); run `make agent` and build \
             again, or connecting to another machine is refused"
        );
    }
}

#[cfg(windows)]
fn main() {
    use std::{env, fs, process::Command};

    embed_agents();

    let icon = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("../../assets/disktree.ico")
        .canonicalize()
        .expect("Windows icon asset is missing");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let rc = out.join("disktree.rc");
    let res = out.join("disktree.res");

    // rc.exe treats backslashes inside quoted paths as separators, not escapes.
    let icon_path = icon.to_string_lossy().replace('\\', "/");
    fs::write(&rc, format!("1 ICON \"{icon_path}\"\n"))
        .expect("could not write Windows icon resource script");

    // Cargo can run outside a Visual Studio prompt, where the SDK bin is not
    // on PATH even though the MSVC linker and Windows SDK are installed.
    let rc_exe = env::var_os("DISKTREE_RC").map_or_else(
        || {
            let sdk_bin = env::var_os("WindowsSdkDir")
                .map(PathBuf::from)
                .or_else(|| {
                    env::var_os("ProgramFiles(x86)")
                        .map(|root| PathBuf::from(root).join("Windows Kits/10"))
                })
                .expect("Windows SDK is required to embed the icon")
                .join("bin");
            let host = match env::consts::ARCH {
                "x86_64" => "x64",
                "aarch64" => "arm64",
                "x86" => "x86",
                other => panic!("unsupported Windows build host: {other}"),
            };
            let mut versions: Vec<_> = fs::read_dir(&sdk_bin)
                .expect("Windows SDK bin directory is missing")
                .filter_map(Result::ok)
                .map(|entry| entry.path().join(host).join("rc.exe"))
                .filter(|path| path.is_file())
                .collect();
            versions.sort();
            versions
                .pop()
                .expect("rc.exe is missing from the Windows SDK")
        },
        PathBuf::from,
    );
    let status = Command::new(rc_exe)
        .arg("/nologo")
        .arg(format!("/fo{}", res.display()))
        .arg(&rc)
        .status()
        .expect("could not start rc.exe to embed the Windows icon");
    assert!(
        status.success(),
        "rc.exe failed to compile the Windows icon"
    );

    println!("cargo:rerun-if-changed={}", icon.display());
    println!("cargo:rustc-link-arg-bin=disktree={}", res.display());
}

#[cfg(not(windows))]
fn main() {
    embed_agents();
}
