//! Scan a root through an agent and print what it cost.
//!
//! ```sh
//! cargo run --release -p disktree-agent --example remote_scan -- \
//!     /run/sparkos/host/home ssh -T spark-2 ~/.cache/disktree/agent serve
//! ```
//!
//! The first argument is the root; the rest is the command that starts
//! the agent. Not a test: it needs a host, and its numbers are the point.

use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::time::Instant;

use disktree_agent::Client;
use disktree_core::scan::ScanOptions;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (Some(root), Some(program)) = (args.next(), args.next()) else {
        eprintln!("usage: remote_scan ROOT AGENT-COMMAND...");
        return ExitCode::from(2);
    };
    let mut command = Command::new(program);
    command.args(args);

    let started = Instant::now();
    let client = match Client::connect(command) {
        Ok(client) => client,
        Err(error) => {
            eprintln!("connect: {error}");
            return ExitCode::FAILURE;
        }
    };
    let hello = client.hello();
    println!(
        "agent {} on {} ({}, {}), protocol {}, in {:.2?}",
        hello.version,
        hello.hostname,
        hello.os,
        hello.arch,
        hello.protocol,
        started.elapsed()
    );

    let scanning = Instant::now();
    let scan = client.scan(&PathBuf::from(root), &ScanOptions::default());
    let tree = match scan.wait() {
        Ok(tree) => tree,
        Err(error) => {
            eprintln!("scan: {error}");
            return ExitCode::FAILURE;
        }
    };
    let wall = scanning.elapsed();
    let progress = scan.progress();
    let transfer = scan.transfer().unwrap_or_default();
    println!("wall time      {wall:.2?}");
    println!("tree transfer  {:.2?}", transfer.elapsed);
    println!("nodes          {}", transfer.nodes);
    println!("files, dirs    {}, {}", tree.files, tree.dirs);
    println!("bytes          {}", tree.bytes);
    println!("read errors    {}", progress.errors);
    println!(
        "raw encoding   {} ({:.2} bytes per node)",
        transfer.raw_bytes,
        transfer.raw_bytes as f64 / transfer.nodes.max(1) as f64
    );
    println!(
        "on the wire    {} ({:.2} bytes per node)",
        transfer.wire_bytes,
        transfer.wire_bytes as f64 / transfer.nodes.max(1) as f64
    );
    ExitCode::SUCCESS
}
