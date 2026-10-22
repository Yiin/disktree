// The id of the sources an agent is built from. Included, not linked, by
// the agent's build script, which stamps the agent and its client with it,
// by the app's, and by `cargo xtask agent`, which writes it beside the
// agents it builds: one algorithm, so the three always agree.

/// Every file the agent binary is built from, relative to the workspace
/// root: its own crate and the core's, tests and examples left out.
const AGENT_SOURCES: [&str; 6] = [
    "crates/disktree-agent/Cargo.toml",
    "crates/disktree-agent/build.rs",
    "crates/disktree-agent/source_id.rs",
    "crates/disktree-agent/src",
    "crates/disktree-core/Cargo.toml",
    "crates/disktree-core/src",
];

/// FNV-1a over each file under [`AGENT_SOURCES`] in `root`, in path order,
/// path and contents both. Not a defence against anyone: it tells a stale
/// build from a current one, on one machine, with any toolchain.
fn agent_source_id(root: &std::path::Path) -> String {
    fn collect(path: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
        if path.is_dir() {
            for entry in std::fs::read_dir(path).into_iter().flatten().flatten()
            {
                collect(&entry.path(), files);
            }
        } else if path.is_file() {
            files.push(path.to_path_buf());
        }
    }
    let mut files = Vec::new();
    for source in AGENT_SOURCES {
        collect(&root.join(source), &mut files);
    }
    files.sort();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for &byte in bytes {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    };
    for file in &files {
        let relative = file.strip_prefix(root).unwrap_or(file);
        feed(relative.to_string_lossy().replace('\\', "/").as_bytes());
        feed(&[0]);
        feed(&std::fs::read(file).unwrap_or_default());
        feed(&[0]);
    }
    format!("{hash:016x}")
}
