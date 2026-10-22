// The id of the sources an agent is built from. Included, not linked, by
// the agent's build script, which stamps the agent and its client with it,
// by the app's, and by `cargo xtask agent`, which writes it beside the
// agents it builds: one algorithm, so the three always agree.

/// What the agent binary is built from, relative to the workspace root:
/// the workspace manifest and lock, which pin every dependency and the
/// release profile, and the agent's and the core's crates.
const AGENT_SOURCES: [&str; 8] = [
    "Cargo.toml",
    "Cargo.lock",
    "crates/disktree-agent/Cargo.toml",
    "crates/disktree-agent/build.rs",
    "crates/disktree-agent/source_id.rs",
    "crates/disktree-agent/src",
    "crates/disktree-core/Cargo.toml",
    "crates/disktree-core/src",
];

/// Whether a file found in a folder of [`AGENT_SOURCES`] is source. Only
/// what cargo reads: an editor's swap file or a merge's `.orig` beside it
/// would change the id between `make agent` and the app's build.
fn is_source(path: &std::path::Path) -> bool {
    path.extension().is_some_and(|extension| extension == "rs")
        || path.file_name().is_some_and(|name| name == "Cargo.toml")
}

/// FNV-1a over each file under [`AGENT_SOURCES`] in `root`, the workspace
/// root, in path order, path and contents both. Not a defence against
/// anyone: it tells a stale build from a current one, on one machine,
/// with any toolchain.
fn agent_source_id(root: &std::path::Path) -> String {
    fn collect(path: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
        if path.is_dir() {
            for entry in std::fs::read_dir(path).into_iter().flatten().flatten()
            {
                let path = entry.path();
                if path.is_dir() || is_source(&path) {
                    collect(&path, files);
                }
            }
        } else if path.is_file() {
            files.push(path.to_path_buf());
        }
    }
    let mut files = Vec::new();
    for source in AGENT_SOURCES {
        collect(&root.join(source), &mut files);
    }
    let mut files: Vec<String> = files
        .iter()
        .map(|file| {
            let relative = file.strip_prefix(root).unwrap_or(file);
            relative.to_string_lossy().replace('\\', "/")
        })
        .collect();
    files.sort();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for &byte in bytes {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    };
    for file in &files {
        feed(file.as_bytes());
        feed(&[0]);
        feed(&std::fs::read(root.join(file)).unwrap_or_default());
        feed(&[0]);
    }
    format!("{hash:016x}")
}
