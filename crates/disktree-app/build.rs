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
    let root = manifest.join("../..");
    let dir = manifest.join("../../target/agent");
    // Watched as a directory, which cargo scans for changes: a path that
    // does not exist would rerun this script, and rebuild the app, on every
    // build. So the folder is made if it is missing.
    let _ = std::fs::create_dir_all(&dir);
    println!("cargo:rerun-if-changed={}", dir.display());
    warn_if_stale(&root, &dir);
    stamp(&root, &dir);
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

/// Stamp the binary with what `--version` reports: the commit it was built
/// from, and the agent it carries.
fn stamp(root: &Path, dir: &Path) {
    println!("cargo:rustc-env=DISKTREE_COMMIT={}", git_commit(root));
    println!(
        "cargo:rustc-env=DISKTREE_EMBEDDED_AGENT={}",
        embedded_agent(dir)
    );
    watch_git(root);
}

/// The short sha of `HEAD`, `-dirty` when a tracked file changed since the
/// commit, and `unknown` outside git or without git on `PATH`. Tracked files
/// only: an untracked file beside the sources is not part of what was built.
fn git_commit(root: &Path) -> String {
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| {
                String::from_utf8_lossy(&output.stdout).trim().to_owned()
            })
    };
    let Some(head) = git(&["rev-parse", "--short=7", "HEAD"]) else {
        return "unknown".to_owned();
    };
    let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
        .is_some_and(|status| !status.is_empty());
    if dirty { format!("{head}-dirty") } else { head }
}

/// The build id of the agents in `dir`, as a client's hello carries it:
/// `no agent` when there are none to embed.
fn embedded_agent(dir: &Path) -> String {
    let any = AGENTS
        .iter()
        .any(|arch| dir.join(format!("disktree-agent-{arch}")).is_file());
    if !any {
        return "no agent".to_owned();
    }
    std::fs::read_to_string(dir.join("build-id"))
        .map_or_else(|_| "unknown agent".to_owned(), |id| id.trim().to_owned())
}

/// Watch the git directory, so a commit restamps the binary without a source
/// edit. In a worktree `.git` is a file naming the worktree's git directory,
/// and the refs a commit moves live in the common directory it points to.
fn watch_git(root: &Path) {
    let dot = root.join(".git");
    let mut watched = vec![dot.clone()];
    if dot.is_file()
        && let Ok(text) = std::fs::read_to_string(&dot)
        && let Some(relative) = text.trim().strip_prefix("gitdir:")
    {
        let gitdir = root.join(relative.trim());
        if let Ok(common) = std::fs::read_to_string(gitdir.join("commondir")) {
            let common = gitdir.join(common.trim());
            watched.push(common.canonicalize().unwrap_or(common));
        }
        watched.push(gitdir);
    }
    // Missing paths would rerun this script on every build; only say what
    // is there.
    for path in watched.iter().filter(|path| path.exists()) {
        println!("cargo:rerun-if-changed={}", path.display());
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
