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
//!   compiler on a desktop does. `ZIG` names it when it is not on `PATH`.

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
    for (triple, ..) in TARGETS {
        has_std(triple)?;
    }
    let zig = zig()?;
    fs::create_dir_all(OUT)
        .map_err(|err| format!("could not create {OUT}: {err}"))?;
    for (triple, arch, machine, zig_target) in TARGETS {
        let compiler = zig_wrappers(&zig, triple, zig_target)?;
        build(cargo, triple, &compiler)?;
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
    Ok(())
}

/// Whether the toolchain running this has `triple`'s standard library.
fn has_std(triple: &str) -> Result<(), String> {
    let output = Command::new("rustc")
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
             rustup: `rustup target add {triple}`, then run `cargo xtask \
             agent` with rustup's cargo first on PATH"
        ))
    }
}

/// zig, from `ZIG` or `PATH`, if it runs.
fn zig() -> Result<String, String> {
    let zig = std::env::var("ZIG").unwrap_or_else(|_| "zig".into());
    let runs = Command::new(&zig)
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if runs {
        Ok(zig)
    } else {
        Err(format!(
            "could not run `{zig} version`: the musl agents need zig \
             (ziglang.org) to compile mimalloc; put it on PATH or set ZIG"
        ))
    }
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

fn build(cargo: &str, triple: &str, compiler: &Compiler) -> Result<(), String> {
    let target = triple.replace('-', "_");
    let linker = format!("CARGO_TARGET_{}_LINKER", target.to_uppercase());
    let status = Command::new(cargo)
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
