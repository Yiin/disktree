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
use rayon::prelude::*;
use ruzstd::encoding::{CompressionLevel, compress_to_vec};

use crate::protocol::{
    Hello, PROTOCOL, PathInfo, Reply, Request, SpaceReport, preamble,
};
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
        // Registered here, before the work starts, so a cancel sent right
        // behind its request is never read before there is a flag to set.
        let cancel = Arc::new(AtomicBool::new(false));
        lock(&agent.cancels).insert(id, Arc::clone(&cancel));
        let agent = Arc::clone(&agent);
        thread::Builder::new()
            .name(format!("disktree-agent-{id}"))
            .spawn(move || {
                // A failed send means the client is gone; the read loop
                // sees the same end and stops.
                let _ = agent.answer(id, request, &cancel);
                lock(&agent.cancels).remove(&id);
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

    fn answer(
        &self,
        id: u64,
        request: Request,
        cancel: &AtomicBool,
    ) -> io::Result<()> {
        match request {
            Request::Scan { root, options } => {
                self.scan(id, root, options, cancel)
            }
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
            } => self.remove(id, &root, &targets, mode, cancel),
            Request::Volumes => {
                self.send(id, &Reply::Volumes(space::volumes()))
            }
            Request::GitState { path } => self
                .send(id, &Reply::GitState(disktree_core::git::state(&path))),
            Request::PathInfo { path } => {
                self.send(id, &Reply::PathInfo(path_info(&path)))
            }
            Request::Cancel => Ok(()),
        }
    }

    fn scan(
        &self,
        id: u64,
        root: PathBuf,
        options: ScanOptions,
        cancel: &AtomicBool,
    ) -> io::Result<()> {
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
                let mut batch = Vec::new();
                let nodes = encode_tree(&tree, CHUNK, |raw| {
                    batch.push(raw.to_vec());
                    if batch.len() >= rayon::current_num_threads() {
                        self.send_compressed(id, &mut batch)?;
                    }
                    Ok(())
                })?;
                self.send_compressed(id, &mut batch)?;
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

    /// Compress `batch` across every core and send it in order. One core
    /// compresses a whole disk's tree about seven times slower than it is
    /// encoded; a batch per core keeps the chunks streaming in order.
    fn send_compressed(
        &self,
        id: u64,
        batch: &mut Vec<Vec<u8>>,
    ) -> io::Result<()> {
        let chunks: Vec<Vec<u8>> = batch
            .par_iter()
            .map(|raw| {
                compress_to_vec(raw.as_slice(), CompressionLevel::Fastest)
            })
            .collect();
        batch.clear();
        for chunk in chunks {
            self.send(id, &Reply::TreeChunk(chunk))?;
        }
        Ok(())
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
        cancel: &AtomicBool,
    ) -> io::Result<()> {
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

fn path_info(path: &Path) -> PathInfo {
    PathInfo {
        canonical: std::fs::canonicalize(path).ok(),
        is_dir: std::fs::metadata(path)
            .map(|metadata| metadata.is_dir())
            .map_err(|error| error.to_string()),
        exists: std::fs::symlink_metadata(path).is_ok(),
    }
}

/// A lock whose holder panicked still guards consistent data here: every
/// critical section is one insert, remove or frame write.
fn lock<T: ?Sized>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{read_preamble, tag};

    /// Collects what the agent writes, for a test to read afterwards.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            lock(&self.0).extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn an_unknown_request_is_answered_and_the_agent_keeps_serving() {
        let mut input = Vec::new();
        // Request 99 from a newer client, id 5, and a body this agent
        // cannot read.
        write_frame(&mut input, 99, &[5, 0xFF, 0xFF]).unwrap();
        let output = Captured::default();
        serve(input.as_slice(), output.clone()).unwrap();

        let written = lock(&output.0).clone();
        let mut stream = written.as_slice();
        assert_eq!(read_preamble(&mut stream).unwrap(), PROTOCOL);
        let (first, hello) = read_frame(&mut stream).unwrap().unwrap();
        assert_eq!(first, tag::HELLO);
        // Volumes carry free space, which moves between two readings.
        let without_volumes = |mut hello: Hello| {
            hello.volumes.clear();
            hello
        };
        assert_eq!(
            without_volumes(Hello::decode(&hello, PROTOCOL).unwrap()),
            without_volumes(super::hello())
        );
        let (failed, payload) = read_frame(&mut stream).unwrap().unwrap();
        assert_eq!(failed, tag::FAILED);
        let (id, reply) = Reply::decode(failed, &payload).unwrap();
        assert_eq!(id, 5);
        assert!(matches!(
            reply,
            Some(Reply::Failed {
                kind: io::ErrorKind::Unsupported,
                ..
            })
        ));
    }
}
