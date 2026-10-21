//! The agent's side: read requests, do the work on this machine, answer.
//!
//! Every request but a cancel gets a thread of its own, so a slow
//! free-space reading on a hung mount never holds up a scan's progress.
//! Replies from all of them share the output, a whole frame at a time.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use disktree_core::removal::{self, RemovalEvent, RemovalMode, Target};
use disktree_core::scan::{ScanHandle, ScanOptions, ScanSnapshot};
use disktree_core::space;
use ruzstd::encoding::{CompressionLevel, compress_to_vec};

use crate::protocol::{Hello, PROTOCOL, Reply, Request, SpaceReport, preamble};
use crate::tree_codec::{CHUNK, encode_tree};
use crate::wire::{read_frame, write_frame};

/// How often a running scan reports, as the app redraws its counters.
const PROGRESS_EVERY: Duration = Duration::from_millis(100);

/// How often a removal's worker is asked for news. Short: each answer is
/// one deleted path the review screen is waiting to tick off.
const REMOVAL_EVERY: Duration = Duration::from_millis(10);

/// What this machine says about itself.
pub fn hello() -> Hello {
    Hello {
        protocol: PROTOCOL,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        os: std::env::consts::OS.to_owned(),
        hostname: hostname(),
        home: std::env::home_dir(),
        mounts: space::mount_table().unwrap_or_default(),
        volumes: space::volumes(),
        trash: removal::detect_trash_backend(),
    }
}

#[cfg(unix)]
fn hostname() -> String {
    rustix::system::uname()
        .nodename()
        .to_string_lossy()
        .into_owned()
}

#[cfg(not(unix))]
fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_default()
}

/// Answer requests from `input` on `output` until `input` ends.
///
/// Work still running then is abandoned with the process, which is what a
/// closed connection means: nobody is left to read the answer.
pub fn serve(
    mut input: impl Read,
    output: impl Write + Send + 'static,
) -> io::Result<()> {
    let agent = Arc::new(Agent {
        output: Mutex::new(Box::new(output)),
        cancels: Mutex::new(HashMap::new()),
    });
    removal::prime_mount_points();
    {
        let mut output = lock(&agent.output);
        output.write_all(&preamble())?;
        write_frame(
            &mut *output,
            crate::protocol::tag::HELLO,
            &hello().encode(),
        )?;
        output.flush()?;
    }
    while let Some((tag, payload)) = read_frame(&mut input)? {
        let (id, request) = Request::decode(tag, &payload)?;
        let Some(request) = request else {
            agent.send(
                id,
                &Reply::Failed {
                    kind: io::ErrorKind::Unsupported,
                    message: format!(
                        "this agent ({}) does not know request {tag}",
                        env!("CARGO_PKG_VERSION")
                    ),
                },
            )?;
            continue;
        };
        if matches!(request, Request::Cancel) {
            let cancel = lock(&agent.cancels).remove(&id);
            if let Some(cancel) = cancel {
                cancel.store(true, Ordering::Relaxed);
            }
            continue;
        }
        let agent = Arc::clone(&agent);
        thread::Builder::new()
            .name(format!("disktree-agent-{id}"))
            .spawn(move || {
                // A failed send means the client is gone; the read loop
                // sees the same end and stops.
                let _ = agent.answer(id, request);
            })?;
    }
    Ok(())
}

struct Agent {
    output: Mutex<Box<dyn Write + Send>>,
    /// Flags that stop the scan or removal with that id.
    cancels: Mutex<HashMap<u64, Arc<AtomicBool>>>,
}

impl Agent {
    fn send(&self, id: u64, reply: &Reply) -> io::Result<()> {
        let (tag, payload) = reply.encode(id);
        let mut output = lock(&self.output);
        write_frame(&mut *output, tag, &payload)?;
        output.flush()
    }

    fn answer(&self, id: u64, request: Request) -> io::Result<()> {
        match request {
            Request::Scan { root, options } => self.scan(id, root, options),
            Request::Space { path } => {
                self.send(id, &Reply::Space(space_report(&path)))
            }
            Request::Plan { root, targets } => {
                self.send(id, &Reply::Plan(removal::plan(&targets, &root)))
            }
            Request::Remove {
                root,
                targets,
                mode,
            } => self.remove(id, &root, &targets, mode),
            Request::Volumes => {
                self.send(id, &Reply::Volumes(space::volumes()))
            }
            Request::Cancel => Ok(()),
        }
    }

    fn cancellable(&self, id: u64) -> Arc<AtomicBool> {
        let flag = Arc::new(AtomicBool::new(false));
        lock(&self.cancels).insert(id, Arc::clone(&flag));
        flag
    }

    fn scan(
        &self,
        id: u64,
        root: PathBuf,
        options: ScanOptions,
    ) -> io::Result<()> {
        let cancel = self.cancellable(id);
        let scan = ScanHandle::spawn(root, options);
        let mut sent = ScanSnapshot::default();
        let outcome = loop {
            if cancel.load(Ordering::Relaxed) {
                scan.cancel();
            }
            let outcome = scan.poll();
            // After the poll, so the last snapshot before the tree is the
            // finished one.
            let snapshot = scan.progress.snapshot();
            if snapshot != sent {
                self.send(id, &Reply::Progress(snapshot.clone()))?;
                sent = snapshot;
            }
            if let Some(outcome) = outcome {
                break outcome;
            }
            thread::sleep(PROGRESS_EVERY);
        };
        lock(&self.cancels).remove(&id);
        match outcome {
            // Whoever cancelled has moved on: a partial tree of a whole
            // disk is a lot of bytes for nobody.
            Ok(_) if scan.progress.is_cancelled() => self.send(
                id,
                &Reply::Failed {
                    kind: io::ErrorKind::Interrupted,
                    message: "the scan was cancelled".into(),
                },
            ),
            Ok(tree) => {
                let nodes = encode_tree(&tree, CHUNK, |raw| {
                    let chunk = compress_to_vec(raw, CompressionLevel::Fastest);
                    self.send(id, &Reply::TreeChunk(chunk))
                })?;
                self.send(id, &Reply::TreeEnd { nodes })
            }
            Err(error) => self.send(
                id,
                &Reply::Failed {
                    kind: error.kind(),
                    message: error.to_string(),
                },
            ),
        }
    }

    /// Remove what this machine's own plan allows, and report what it
    /// refused as failures: the client's idea of what is safe here is
    /// never what decides.
    fn remove(
        &self,
        id: u64,
        root: &Path,
        targets: &[Target],
        mode: RemovalMode,
    ) -> io::Result<()> {
        let cancel = self.cancellable(id);
        let plan = removal::plan(targets, root);
        let refused: Vec<RemovalEvent> = plan
            .blocked
            .iter()
            .map(|blocked| RemovalEvent::Item {
                path: blocked.path.clone(),
                bytes: targets
                    .iter()
                    .find(|target| target.path == blocked.path)
                    .map_or(0, |target| target.bytes),
                outcome: Err(format!("refused: {}", blocked.reason)),
            })
            .collect();
        let run = removal::spawn(plan, mode);
        let mut cancelled = false;
        loop {
            if !cancelled && cancel.load(Ordering::Relaxed) {
                run.cancel();
                cancelled = true;
            }
            let Some(event) = run.poll() else {
                thread::sleep(REMOVAL_EVERY);
                continue;
            };
            match event {
                RemovalEvent::Start { total } => {
                    self.send(
                        id,
                        &Reply::Removal(RemovalEvent::Start {
                            total: total + refused.len(),
                        }),
                    )?;
                    for item in &refused {
                        self.send(id, &Reply::Removal(item.clone()))?;
                    }
                }
                RemovalEvent::Done {
                    removed,
                    bytes,
                    failed,
                } => {
                    lock(&self.cancels).remove(&id);
                    return self.send(
                        id,
                        &Reply::Removal(RemovalEvent::Done {
                            removed,
                            bytes,
                            failed: failed + refused.len(),
                        }),
                    );
                }
                item @ RemovalEvent::Item { .. } => {
                    self.send(id, &Reply::Removal(item))?;
                }
            }
        }
    }
}

fn space_report(path: &Path) -> SpaceReport {
    SpaceReport {
        space: space::space_info(path).map_err(|error| error.to_string()),
        device: space::device_for(path),
        volume_root: space::volume_root_for(path),
    }
}

/// A lock whose holder panicked still guards consistent data here: every
/// critical section is one insert, remove or frame write.
fn lock<T: ?Sized>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
