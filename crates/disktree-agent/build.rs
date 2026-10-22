//! Stamp the agent, and the client that talks to it, with the id of the
//! sources they are built from; see `source_id.rs`.

include!("source_id.rs");

fn main() {
    let manifest = std::path::PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").unwrap(),
    );
    let root = manifest.join("../..");
    for source in AGENT_SOURCES {
        println!("cargo:rerun-if-changed={}", root.join(source).display());
    }
    println!(
        "cargo:rustc-env=DISKTREE_AGENT_BUILD={}",
        agent_source_id(&root)
    );
}
