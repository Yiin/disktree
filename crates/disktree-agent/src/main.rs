//! `disktree-agent serve`: answer a disktree client on stdin and stdout.

use std::fs::File;
use std::io::{self, BufWriter};
use std::process::ExitCode;

use disktree_agent::PROTOCOL;

/// See the manifest: musl's own allocator serializes a parallel scan.
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

const USAGE: &str = "\
usage: disktree-agent serve       answer a disktree client on stdin/stdout
       disktree-agent --version
";

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("serve") => match serve() {
            // Scans or removals still running belong to a client that has
            // gone; exiting here ends them with it.
            Ok(()) => std::process::exit(0),
            Err(error) => {
                eprintln!("disktree-agent: {error}");
                std::process::exit(1)
            }
        },
        Some("--version" | "-V") => {
            println!(
                "disktree-agent {} (protocol {PROTOCOL})",
                env!("CARGO_PKG_VERSION")
            );
            ExitCode::SUCCESS
        }
        _ => {
            eprint!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn serve() -> io::Result<()> {
    disktree_agent::serve(
        io::stdin(),
        BufWriter::with_capacity(1 << 16, raw_stdout()?),
    )
}

/// Stdout as a plain file: `io::Stdout` flushes at every newline byte,
/// and a tree chunk is full of them.
#[cfg(unix)]
fn raw_stdout() -> io::Result<File> {
    use std::os::fd::AsFd;
    Ok(File::from(io::stdout().as_fd().try_clone_to_owned()?))
}

#[cfg(windows)]
fn raw_stdout() -> io::Result<File> {
    use std::os::windows::io::AsHandle;
    Ok(File::from(io::stdout().as_handle().try_clone_to_owned()?))
}
