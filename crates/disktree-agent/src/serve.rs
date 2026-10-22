//! The agent's side: read requests, do the work on this machine, answer.
//!
//! Every request but a cancel gets a thread of its own, so a slow
//! free-space reading on a hung mount never holds up a scan's progress.
//! Replies from all of them share the output, a whole frame at a time.
//!
//! The client's input is read on a thread of its own too, so a frame from
//! it, a ping at least, is heard however long a reply takes to write.
//! [`SILENCE`] without one means the link stopped passing packets without
//! closing, and the agent ends as if the input had.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
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

/// How long the agent waits for any frame from the client before it takes
/// the client for gone.
///
/// The client pings every 5 s; four of those missed is a dead link, not a
/// busy one, since pings are sent and read on threads that no scan or
/// transfer holds up.
pub const SILENCE: Duration = Duration::from_secs(20);

/// What this machine says about itself.
pub fn hello() -> Hello {
    Hello {
        protocol: PROTOCOL,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        build: crate::protocol::BUILD.to_owned(),
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

/// Answer requests from `input` on `output` until `input` ends, or says
/// nothing for [`SILENCE`].
///
/// Work still running then is cancelled, and abandoned with the process,
/// which is what a closed connection means: nobody is left to read the
/// answer, or to cancel it. A silent one fails with
/// [`io::ErrorKind::TimedOut`].
pub fn serve(
    input: impl Read + Send + 'static,
    output: impl Write + Send + 'static,
) -> io::Result<()> {
    serve_until_silent(input, output, SILENCE)
}

/// [`serve`], with the client taken for gone after `silence`.
fn serve_until_silent(
    input: impl Read + Send + 'static,
    output: impl Write + Send + 'static,
    silence: Duration,
) -> io::Result<()> {
    let agent = Arc::new(Agent {
        output: Mutex::new(Box::new(output)),
        cancels: Mutex::new(HashMap::new()),
        gone: AtomicBool::new(false),
    });
    let served = answer_requests(&agent, input, silence);
    agent.gone.store(true, Ordering::Relaxed);
    for cancel in lock(&agent.cancels).values() {
        cancel.store(true, Ordering::Relaxed);
    }
    served
}

/// The hello, then every request from `input` until it ends or falls
/// silent.
fn answer_requests(
    agent: &Arc<Agent>,
    input: impl Read + Send + 'static,
    silence: Duration,
) -> io::Result<()> {
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
    let frames = read_frames(input)?;
    loop {
        let (tag, payload) = match frames.recv_timeout(silence) {
            Ok(Ok(Some(frame))) => frame,
            Ok(Ok(None)) | Err(RecvTimeoutError::Disconnected) => {
                return Ok(());
            }
            Ok(Err(error)) => return Err(error),
            Err(RecvTimeoutError::Timeout) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "no word from the client for {} s: the link is lost",
                        silence.as_secs_f32()
                    ),
                ));
            }
        };
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
        if matches!(request, Request::Ping) {
            continue;
        }
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
        let agent = Arc::clone(agent);
        thread::Builder::new()
            .name(format!("disktree-agent-{id}"))
            .spawn(move || {
                // A failed send means the client is gone; the read loop
                // sees the same end and stops.
                let _ = agent.answer(id, request, &cancel);
                lock(&agent.cancels).remove(&id);
            })?;
    }
}

/// A frame from the client, or how its input ended.
type Frame = io::Result<Option<(u8, Vec<u8>)>>;

/// Every frame from `input` as it arrives, then how it ended. Read apart
/// from the requests' work, so silence is the link's and not the agent's.
fn read_frames(
    input: impl Read + Send + 'static,
) -> io::Result<mpsc::Receiver<Frame>> {
    let (frames, arrived) = mpsc::channel();
    thread::Builder::new()
        .name("disktree-agent-input".into())
        .spawn(move || {
            let mut input = input;
            loop {
                let frame = read_frame(&mut input);
                let last = !matches!(frame, Ok(Some(_)));
                if frames.send(frame).is_err() || last {
                    return;
                }
            }
        })?;
    Ok(arrived)
}

struct Agent {
    output: Mutex<Box<dyn Write + Send>>,
    /// Flags that stop the scan or removal with that id.
    cancels: Mutex<HashMap<u64, Arc<AtomicBool>>>,
    /// Whether the client has gone: its input ended, or a reply to it
    /// could not be written. A removal stops for nobody else.
    gone: AtomicBool,
}

impl Agent {
    fn send(&self, id: u64, reply: &Reply) -> io::Result<()> {
        let (tag, payload) = reply.encode(id);
        let mut output = lock(&self.output);
        let sent = write_frame(&mut *output, tag, &payload)
            .and_then(|()| output.flush());
        drop(output);
        if sent.is_err() {
            self.gone.store(true, Ordering::Relaxed);
        }
        sent
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
            Request::Plan { root, targets }
            | Request::Remove { root, targets, .. }
                if let Some(reason) = unanchored(&root, &targets) =>
            {
                self.send(
                    id,
                    &Reply::Failed {
                        kind: io::ErrorKind::InvalidInput,
                        message: reason,
                    },
                )
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
            Request::Cancel | Request::Ping => Ok(()),
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
    ///
    /// The start is said before anything is touched, so a client that
    /// cannot be written to gets nothing removed. Once one cannot be
    /// written to, or its input ends, the removal stops before its next
    /// target: nobody could see it, or cancel it.
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
        self.send(
            id,
            &Reply::Removal(RemovalEvent::Start {
                total: plan.targets.len() + refused.len(),
            }),
        )?;
        for item in &refused {
            self.send(id, &Reply::Removal(item.clone()))?;
        }
        let run = removal::spawn(plan, mode);
        let mut cancelled = false;
        loop {
            if !cancelled
                && (cancel.load(Ordering::Relaxed)
                    || self.gone.load(Ordering::Relaxed))
            {
                run.cancel();
                cancelled = true;
            }
            let Some(event) = run.poll() else {
                thread::sleep(REMOVAL_EVERY);
                continue;
            };
            let event = match event {
                // Already said, with the refused ones counted.
                RemovalEvent::Start { .. } => continue,
                RemovalEvent::Done {
                    removed,
                    bytes,
                    failed,
                } => RemovalEvent::Done {
                    removed,
                    bytes,
                    failed: failed + refused.len(),
                },
                event @ (RemovalEvent::Item { .. }
                | RemovalEvent::Lost { .. }) => event,
            };
            let last = !matches!(event, RemovalEvent::Item { .. });
            if let Err(error) = self.send(id, &Reply::Removal(event)) {
                run.cancel();
                return Err(error);
            }
            if last {
                return Ok(());
            }
        }
    }
}

/// Why a plan or a removal is refused before anything is judged: the
/// root and every target must be absolute, with no `..` to resolve. The
/// guards compare spellings, and a root of `""` or `.` normalizes to the
/// empty path, which every path starts with: it would lift the limit to
/// the scanned root. A relative one would be taken from wherever the
/// agent was started. The app never sends either; the agent does not
/// count on that.
fn unanchored(root: &Path, targets: &[Target]) -> Option<String> {
    let anchored = |path: &Path| {
        path.is_absolute()
            && !path.components().any(|part| part == Component::ParentDir)
    };
    // Quoted, so an empty root still shows.
    if !anchored(root) {
        return Some(format!(
            "the scanned root \u{201c}{}\u{201d} is not an absolute path: \
             nothing was judged or removed",
            root.display()
        ));
    }
    targets.iter().find(|target| !anchored(&target.path)).map(|target| {
        format!(
            "\u{201c}{}\u{201d} is not an absolute path: nothing was judged \
             or removed",
            target.path.display()
        )
    })
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

    /// Output that works until `broken` is set, then fails every write
    /// the way a closed pipe does.
    #[derive(Clone, Default)]
    struct Breakable {
        written: Captured,
        broken: Arc<AtomicBool>,
    }

    impl Write for Breakable {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.broken.load(Ordering::Relaxed) {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            self.written.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// `count` directories of `files` small files each, under `root`.
    fn directories(root: &Path, count: usize, files: usize) -> Vec<Target> {
        (0..count)
            .map(|index| {
                let dir = root.join(format!("d{index}"));
                std::fs::create_dir(&dir).unwrap();
                for file in 0..files {
                    std::fs::write(dir.join(format!("f{file}")), b"x").unwrap();
                }
                Target {
                    path: dir,
                    bytes: 1,
                    is_dir: true,
                    hidden: false,
                }
            })
            .collect()
    }

    fn remaining(targets: &[Target]) -> usize {
        targets.iter().filter(|target| target.path.exists()).count()
    }

    fn remove_frame(root: &Path, targets: &[Target]) -> Vec<u8> {
        let remove = Request::Remove {
            root: root.to_path_buf(),
            targets: targets.to_vec(),
            mode: RemovalMode::Permanent,
        };
        frame(&remove, 1)
    }

    /// A client that can no longer be written to gets nothing removed:
    /// the start is said before the first target is touched.
    #[test]
    fn a_removal_never_starts_for_a_client_it_cannot_write_to() {
        let temp = tempfile::tempdir().unwrap();
        let targets = directories(temp.path(), 20, 1);
        let (reader, mut writer) = io::pipe().unwrap();
        let output = Breakable::default();
        let serving = thread::spawn({
            let output = output.clone();
            move || serve(reader, output)
        });
        while lock(&output.written.0).is_empty() {
            thread::sleep(Duration::from_millis(1));
        }
        output.broken.store(true, Ordering::Relaxed);
        writer
            .write_all(&remove_frame(temp.path(), &targets))
            .unwrap();
        // The answer fails to send; give the request time to reach it.
        thread::sleep(Duration::from_millis(300));
        drop(writer);
        serving.join().unwrap().unwrap();
        thread::sleep(Duration::from_millis(100));
        assert_eq!(remaining(&targets), targets.len(), "nothing removed");
    }

    /// When the client's input ends mid-removal, the removal stops before
    /// its next target instead of running to the end for nobody.
    #[test]
    fn a_removal_stops_when_its_client_goes() {
        let temp = tempfile::tempdir().unwrap();
        let targets = directories(temp.path(), 200, 200);
        let (reader, mut writer) = io::pipe().unwrap();
        let serving = thread::spawn(move || serve(reader, Captured::default()));
        writer
            .write_all(&remove_frame(temp.path(), &targets))
            .unwrap();
        let started = std::time::Instant::now();
        while remaining(&targets) == targets.len() {
            assert!(started.elapsed() < Duration::from_secs(30), "no start");
            thread::sleep(Duration::from_millis(1));
        }
        drop(writer);
        serving.join().unwrap().unwrap();
        // Long enough for every target to go, had it gone on.
        thread::sleep(Duration::from_millis(1500));
        let left = remaining(&targets);
        assert!(left >= targets.len() / 2, "only {left} of 200 were left");
        thread::sleep(Duration::from_millis(200));
        assert_eq!(remaining(&targets), left, "it stopped");
    }

    fn frame(request: &Request, id: u64) -> Vec<u8> {
        let (tag, payload) = request.encode(id);
        let mut frame = Vec::new();
        write_frame(&mut frame, tag, &payload).unwrap();
        frame
    }

    /// A link that stops passing packets without closing: the input stays
    /// open and says nothing. The agent takes the client for gone at the
    /// deadline and stops the removal before its next target.
    #[test]
    fn a_removal_stops_when_its_client_falls_silent() {
        let temp = tempfile::tempdir().unwrap();
        let targets = directories(temp.path(), 200, 200);
        let (reader, mut writer) = io::pipe().unwrap();
        let silence = Duration::from_millis(200);
        let serving = thread::spawn(move || {
            serve_until_silent(reader, Captured::default(), silence)
        });
        writer
            .write_all(&remove_frame(temp.path(), &targets))
            .unwrap();
        let started = std::time::Instant::now();
        let error = serving.join().unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
        assert!(started.elapsed() < Duration::from_secs(5), "it waited");
        // Long enough for every target to go, had it gone on.
        thread::sleep(Duration::from_millis(1500));
        let left = remaining(&targets);
        assert!(left > 0, "every target went");
        thread::sleep(Duration::from_millis(200));
        assert_eq!(remaining(&targets), left, "it stopped");
        // Still open: the silence alone ended it.
        drop(writer);
    }

    /// Output that holds every write while `stalled` is set: a reply that
    /// takes long to cross a slow link.
    #[derive(Clone, Default)]
    struct Stallable {
        written: Captured,
        stalled: Arc<AtomicBool>,
    }

    impl Write for Stallable {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            while self.stalled.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(1));
            }
            self.written.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A scan whose replies are held up for many deadlines still ends
    /// with its tree, as long as the client keeps pinging: pings are read
    /// apart from the work.
    #[test]
    fn a_long_scan_with_pings_completes() {
        let temp = tempfile::tempdir().unwrap();
        directories(temp.path(), 10, 10);
        let (reader, mut writer) = io::pipe().unwrap();
        let output = Stallable::default();
        let silence = Duration::from_millis(200);
        let serving = thread::spawn({
            let output = output.clone();
            move || serve_until_silent(reader, output, silence)
        });
        while lock(&output.written.0).is_empty() {
            thread::sleep(Duration::from_millis(1));
        }
        output.stalled.store(true, Ordering::Relaxed);
        let scan = Request::Scan {
            root: temp.path().to_path_buf(),
            options: ScanOptions::default(),
        };
        writer.write_all(&frame(&scan, 1)).unwrap();
        let started = std::time::Instant::now();
        while started.elapsed() < silence * 5 {
            writer.write_all(&frame(&Request::Ping, 0)).unwrap();
            thread::sleep(silence / 4);
        }
        output.stalled.store(false, Ordering::Relaxed);
        let ended = |written: &[u8]| {
            let mut stream = written;
            read_preamble(&mut stream).unwrap();
            std::iter::from_fn(|| read_frame(&mut stream).ok().flatten())
                .any(|(tag, _)| tag == tag::TREE_END)
        };
        while !ended(&lock(&output.written.0)) {
            assert!(!serving.is_finished(), "the agent stopped serving");
            writer.write_all(&frame(&Request::Ping, 0)).unwrap();
            thread::sleep(silence / 4);
        }
        drop(writer);
        serving.join().unwrap().unwrap();
    }

    #[test]
    fn an_unknown_request_is_answered_and_the_agent_keeps_serving() {
        let mut input = Vec::new();
        // Request 99 from a newer client, id 5, and a body this agent
        // cannot read.
        write_frame(&mut input, 99, &[5, 0xFF, 0xFF]).unwrap();
        let output = Captured::default();
        serve(io::Cursor::new(input), output.clone()).unwrap();

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
