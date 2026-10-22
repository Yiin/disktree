//! `cargo xtask agent`: the remote agent for every Linux machine disktree
//! can reach, as static binaries in `target/agent/`.
//!
//! musl, so the binary runs on any distribution's libc or none, and linked
//! by the `rust-lld` every toolchain ships. Two things must be installed:
//!
//! * each target's standard library, which rustup adds (`rustup target
//!   add`); a distribution's Rust has only its host's, so the check below
//!   says so instead of a page of linker errors;
//! * zig, as the C compiler for mimalloc (see the agent's manifest): it
//!   carries musl's headers for every architecture, which no other
//!   compiler on a desktop does.
//!
//! Both are found without a long `PATH` line: rustup in `RUSTUP_HOME` and
//! `CARGO_HOME`, by default `~/.local/share/rustup` and
//! `~/.local/share/cargo`, where a user-level install keeps it beside a
//! distribution's Rust; zig in `ZIG`, then on `PATH`, then the newest
//! `~/.local/share/zig/*/zig`. Without a rustup there, the cargo and rustc
//! running this are used.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Each target, the name its binary gets, the ELF machine number the
/// result must carry, and zig's spelling of the target.
const TARGETS: [(&str, &str, u16, &str); 2] = [
    (
        "aarch64-unknown-linux-musl",
        "aarch64",
        0xB7,
        "aarch64-linux-musl",
    ),
    (
        "x86_64-unknown-linux-musl",
        "x86_64",
        0x3E,
        "x86_64-linux-musl",
    ),
];

const OUT: &str = "target/agent";

pub fn agent(cargo: &str) -> Result<(), String> {
    let toolchain = Toolchain::find(cargo);
    for (triple, ..) in TARGETS {
        has_std(&toolchain, triple)?;
    }
    let zig = zig()?;
    fs::create_dir_all(OUT)
        .map_err(|err| format!("could not create {OUT}: {err}"))?;
    for (triple, arch, machine, zig_target) in TARGETS {
        let compiler = zig_wrappers(&zig, triple, zig_target)?;
        build(&toolchain, triple, &compiler)?;
        let built: PathBuf = ["target", triple, "release", "disktree-agent"]
            .iter()
            .collect();
        let out = Path::new(OUT).join(format!("disktree-agent-{arch}"));
        fs::copy(&built, &out).map_err(|err| {
            format!(
                "could not copy {} to {}: {err}",
                built.display(),
                out.display()
            )
        })?;
        check_machine(&out, machine)?;
        let size = fs::metadata(&out)
            .map_err(|err| format!("{}: {err}", out.display()))?
            .len();
        println!("{}  {size} bytes  sha256 {}", out.display(), sha256(&out)?);
    }
    write_build_id()
}

include!("../../crates/disktree-agent/source_id.rs");

/// Where the id of the sources the agents in [`OUT`] were built from is
/// written, for the app's build script to compare with its own.
const BUILD_ID: &str = "target/agent/build-id";

/// Write [`BUILD_ID`]. The agents carry the same id themselves and say it
/// in their hello, where the client refuses one that differs; this lets
/// the build warn before that.
fn write_build_id() -> Result<(), String> {
    let id = agent_source_id(Path::new("."));
    fs::write(BUILD_ID, format!("{id}\n"))
        .map_err(|err| format!("could not write {BUILD_ID}: {err}"))?;
    println!("{BUILD_ID}  {id}");
    Ok(())
}

/// The cargo and rustc that build the agents, and what they need in their
/// environment.
struct Toolchain {
    cargo: PathBuf,
    rustc: PathBuf,
    /// rustup's variables and its `bin` first on `PATH`, so whatever cargo
    /// runs is rustup's too; empty for the toolchain running this.
    env: Vec<(&'static str, OsString)>,
}

impl Toolchain {
    /// rustup's when `CARGO_HOME` (default `~/.local/share/cargo`) has its
    /// cargo and `RUSTUP_HOME` (default `~/.local/share/rustup`) is there,
    /// else `running`, the cargo running this, and `rustc` from `PATH`.
    fn find(running: &str) -> Self {
        let data = std::env::home_dir().map(|home| home.join(".local/share"));
        let dir = |var: &str, name: &str| {
            std::env::var_os(var)
                .map(PathBuf::from)
                .or_else(|| data.as_ref().map(|data| data.join(name)))
        };
        let fallback = Self {
            cargo: PathBuf::from(running),
            rustc: PathBuf::from("rustc"),
            env: Vec::new(),
        };
        let (Some(cargo_home), Some(rustup_home)) =
            (dir("CARGO_HOME", "cargo"), dir("RUSTUP_HOME", "rustup"))
        else {
            return fallback;
        };
        let bin = cargo_home.join("bin");
        let exe = |name: &str| {
            bin.join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
        };
        if !exe("cargo").is_file() || !rustup_home.is_dir() {
            return fallback;
        }
        let path = std::env::var_os("PATH").unwrap_or_default();
        let path = std::env::join_paths(
            std::iter::once(bin.clone()).chain(std::env::split_paths(&path)),
        )
        .unwrap_or(path);
        Self {
            cargo: exe("cargo"),
            rustc: exe("rustc"),
            env: vec![
                ("CARGO_HOME", cargo_home.into_os_string()),
                ("RUSTUP_HOME", rustup_home.into_os_string()),
                ("PATH", path),
            ],
        }
    }

    fn command(&self, program: &Path) -> Command {
        let mut command = Command::new(program);
        command.envs(self.env.iter().map(|(key, value)| (key, value)));
        command
    }
}

/// Whether the toolchain has `triple`'s standard library.
fn has_std(toolchain: &Toolchain, triple: &str) -> Result<(), String> {
    let output = toolchain
        .command(&toolchain.rustc)
        .args(["--print", "target-libdir", "--target", triple])
        .stderr(Stdio::null())
        .output()
        .map_err(|err| format!("could not run rustc: {err}"))?;
    let libdir = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let present = output.status.success()
        && fs::read_dir(&libdir).is_ok_and(|entries| {
            entries.flatten().any(|entry| {
                entry.file_name().to_string_lossy().starts_with("libstd-")
            })
        });
    if present {
        Ok(())
    } else {
        Err(format!(
            "this toolchain has no standard library for {triple}. With \
             rustup: `rustup target add {triple}`; a rustup outside \
             ~/.local/share is named by RUSTUP_HOME and CARGO_HOME"
        ))
    }
}

/// zig, from `ZIG`, `PATH` or `~/.local/share/zig`, if it runs.
fn zig() -> Result<String, String> {
    let runs = |zig: &str| {
        Command::new(zig)
            .arg("version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    };
    if let Ok(zig) = std::env::var("ZIG") {
        return if runs(&zig) {
            Ok(zig)
        } else {
            Err(format!("could not run `{zig} version` (from ZIG)"))
        };
    }
    if runs("zig") {
        return Ok("zig".into());
    }
    // An unpacked release is a folder named for its version; the last in
    // name order is the newest of one version scheme.
    let unpacked = std::env::home_dir()
        .map(|home| home.join(".local/share/zig"))
        .and_then(|dir| fs::read_dir(dir).ok())
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path().join("zig"))
        .filter(|zig| zig.is_file())
        .max();
    if let Some(zig) = unpacked.map(|zig| zig.to_string_lossy().into_owned())
        && runs(&zig)
    {
        return Ok(zig);
    }
    Err(
        "the musl agents need zig (ziglang.org) to compile mimalloc: put \
         it on PATH, unpack it under ~/.local/share/zig, or set ZIG"
            .into(),
    )
}

/// The C compiler and archiver the `cc` crate will run for `triple`.
struct Compiler {
    cc: PathBuf,
    ar: PathBuf,
}

/// Scripts that run zig for `triple`. The `cc` crate passes clang a
/// `--target` in rustc's spelling, which zig does not read; zig gets its
/// own instead.
#[cfg(unix)]
fn zig_wrappers(
    zig: &str,
    triple: &str,
    zig_target: &str,
) -> Result<Compiler, String> {
    use std::os::unix::fs::PermissionsExt;

    let dir = Path::new(OUT).join("zig");
    fs::create_dir_all(&dir)
        .map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    let dir = fs::canonicalize(&dir)
        .map_err(|err| format!("{}: {err}", dir.display()))?;
    let cc = dir.join(format!("{triple}-cc"));
    let ar = dir.join(format!("{triple}-ar"));
    let scripts = [
        (
            &cc,
            format!(
                "#!/bin/sh\n\
                 # Written by `cargo xtask agent`.\n\
                 for arg; do\n\
                 \tshift\n\
                 \tcase \"$arg\" in --target=*) ;; *) set -- \"$@\" \"$arg\" ;; esac\n\
                 done\n\
                 exec '{zig}' cc -target {zig_target} \"$@\"\n"
            ),
        ),
        (
            &ar,
            format!(
                "#!/bin/sh\n# Written by `cargo xtask agent`.\n\
                 exec '{zig}' ar \"$@\"\n"
            ),
        ),
    ];
    for (path, script) in scripts {
        fs::write(path, script)
            .and_then(|()| {
                fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            })
            .map_err(|err| format!("{}: {err}", path.display()))?;
    }
    Ok(Compiler { cc, ar })
}

#[cfg(not(unix))]
fn zig_wrappers(_: &str, _: &str, _: &str) -> Result<Compiler, String> {
    Err("build the agents on Linux or macOS".into())
}

fn build(
    toolchain: &Toolchain,
    triple: &str,
    compiler: &Compiler,
) -> Result<(), String> {
    let target = triple.replace('-', "_");
    let linker = format!("CARGO_TARGET_{}_LINKER", target.to_uppercase());
    let cargo = toolchain.cargo.display();
    let status = toolchain
        .command(&toolchain.cargo)
        .args([
            "build",
            "--release",
            "--package",
            "disktree-agent",
            "--bin",
            "disktree-agent",
            "--target",
            triple,
        ])
        .env(linker, "rust-lld")
        .env(format!("CC_{target}"), &compiler.cc)
        .env(format!("AR_{target}"), &compiler.ar)
        // Only for this build: it lands in target/<triple>, so the host's
        // release build keeps its symbols and its cache.
        .env("CARGO_PROFILE_RELEASE_STRIP", "symbols")
        .stdin(Stdio::null())
        .status()
        .map_err(|err| format!("could not start {cargo}: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("the {triple} build failed"))
    }
}

/// The ELF header's machine field: a binary for the wrong machine would
/// install and then fail on the far side with "Exec format error".
fn check_machine(path: &Path, machine: u16) -> Result<(), String> {
    let bytes =
        fs::read(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let found = bytes
        .get(18..20)
        .filter(|_| bytes.starts_with(b"\x7fELF"))
        .map(|field| u16::from_le_bytes([field[0], field[1]]));
    if found == Some(machine) {
        Ok(())
    } else {
        Err(format!(
            "{} is not an ELF binary for machine {machine:#x}",
            path.display()
        ))
    }
}

/// From the system's own tool: GNU `sha256sum`, or `shasum` on macOS.
fn sha256(path: &Path) -> Result<String, String> {
    for (tool, args) in [("sha256sum", &[][..]), ("shasum", &["-a", "256"][..])]
    {
        let Ok(output) = Command::new(tool).args(args).arg(path).output()
        else {
            continue;
        };
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            if let Some(hash) = text.split_whitespace().next() {
                return Ok(hash.to_owned());
            }
        }
    }
    Err("neither sha256sum nor shasum is installed".into())
}
