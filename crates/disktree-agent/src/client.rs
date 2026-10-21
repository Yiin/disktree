//! The app's side: start an agent, usually through `ssh -T host agent
//! serve`, and use it the way the local scan, space and removal calls are
//! used.
//!
//! One reader thread owns the agent's output and hands each reply to the
//! request it answers, so callers block on their own channel and nothing
//! polls. A scan or removal gets a thread of its own that turns replies
//! into what [`ScanHandle`] and [`RemovalHandle`] give locally.
//!
//! [`ScanHandle`]: disktree_core::scan::ScanHandle
//! [`RemovalHandle`]: disktree_core::removal::RemovalHandle

use std::collections::HashMap;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use disktree_core::removal::{Plan, RemovalEvent, RemovalMode, Target};
use disktree_core::scan::{ScanOptions, ScanSnapshot};
use disktree_core::space::Volume;
use disktree_core::tree::Node;
use ruzstd::decoding::StreamingDecoder;

use crate::protocol::{
    Hello, PROTOCOL, Reply, Request, SpaceReport, read_preamble, tag,
};
use crate::tree_codec::{CHUNK, TreeBuilder};
use crate::wire::{invalid, read_frame};

/// How long an agent has to introduce itself: ssh's own connection and
/// key exchange included, with room for a slow link.
const HANDSHAKE: Duration = Duration::from_secs(30);

/// How much of the agent's stderr is kept for an error message: the tail
/// of an ssh failure or a crash, not a log.
const STDERR_TAIL: usize = 4096;

/// A running agent.
#[derive(Debug)]
pub struct Client {
    hello: Hello,
    shared: Arc<Shared>,
    child: Child,
}

#[derive(Debug)]
struct Shared {
    stdin: Mutex<Option<ChildStdin>>,
    routes: Mutex<Routes>,
    stderr: Arc<Mutex<Vec<u8>>>,
    next_id: AtomicU64,
}

#[derive(Debug, Default)]
struct Routes {
    /// Where the replies to each open request go.
    open: HashMap<u64, Sender<Reply>>,
    /// Why the connection ended, once it has.
    closed: Option<String>,
}

impl Client {
    /// Start `command`, which must run `disktree-agent serve` (directly,
    /// or through ssh), and wait for it to introduce itself.
    ///
    /// Fails when it is not an agent, speaks another protocol, exits, or
    /// says nothing for [`HANDSHAKE`]; the error carries what it wrote
    /// to stderr, which is where ssh explains itself.
    pub fn connect(mut command: Command) -> io::Result<Self> {
        let program = command.get_program().to_string_lossy().into_owned();
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("could not start {program}: {error}"),
                )
            })?;
        let (Some(stdin), Some(stdout), Some(stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            return Err(io::Error::other("the agent's pipes were not set up"));
        };
        let stderr_tail = Arc::new(Mutex::new(Vec::new()));
        let stderr_done = keep_tail(stderr, Arc::clone(&stderr_tail));
        let shared = Arc::new(Shared {
            stdin: Mutex::new(Some(stdin)),
            routes: Mutex::new(Routes::default()),
            stderr: stderr_tail,
            next_id: AtomicU64::new(1),
        });

        let (introduced, introduction) = mpsc::channel();
        let reader = Arc::clone(&shared);
        thread::Builder::new()
            .name("disktree-agent-reader".into())
            .spawn(move || {
                read_replies(stdout, &reader, &introduced, &stderr_done);
            })?;

        let outcome = match introduction.recv_timeout(HANDSHAKE) {
            Ok(outcome) => outcome,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                with_stderr(
                    format!(
                        "{program} did not answer as a disktree agent within \
                         {} s",
                        HANDSHAKE.as_secs()
                    ),
                    &shared.stderr,
                ),
            )),
        };
        match outcome {
            Ok(hello) => Ok(Self {
                hello,
                shared,
                child,
            }),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(error)
            }
        }
    }

    /// What the agent said about itself and its machine.
    pub const fn hello(&self) -> &Hello {
        &self.hello
    }

    /// Start walking `root` on the agent's machine.
    pub fn scan(&self, root: &Path, options: &ScanOptions) -> RemoteScan {
        let (id, replies) = self.shared.open(&Request::Scan {
            root: root.to_path_buf(),
            options: options.clone(),
        });
        let progress = Arc::new(Mutex::new(ScanSnapshot::default()));
        let transfer = Arc::new(Mutex::new(None));
        let (sender, result) = mpsc::channel();
        let worker = thread::Builder::new()
            .name(format!("disktree-remote-scan-{id}"))
            .spawn({
                let progress = Arc::clone(&progress);
                let transfer = Arc::clone(&transfer);
                move || {
                    let outcome = receive_tree(&replies, &progress, &transfer);
                    lock(&progress).finished = true;
                    let _ = sender.send(outcome);
                }
            });
        // As with a local scan, a worker that never started leaves the
        // channel closed, and `poll` says so.
        drop(worker);
        RemoteScan {
            id,
            shared: Arc::clone(&self.shared),
            progress,
            result,
            transfer,
        }
    }

    /// Free space where `path` is, and which volume holds it, on the
    /// agent's machine.
    pub fn space(&self, path: &Path) -> io::Result<SpaceReport> {
        match self.shared.call(&Request::Space {
            path: path.to_path_buf(),
        })? {
            Reply::Space(report) => Ok(report),
            other => Err(unexpected(&other)),
        }
    }

    /// The volumes worth scanning there, read now.
    pub fn volumes(&self) -> io::Result<Vec<Volume>> {
        match self.shared.call(&Request::Volumes)? {
            Reply::Volumes(volumes) => Ok(volumes),
            other => Err(unexpected(&other)),
        }
    }

    /// [`disktree_core::removal::plan`], judged on the agent's machine
    /// against its mounts and home directory.
    pub fn plan(&self, targets: &[Target], root: &Path) -> io::Result<Plan> {
        match self.shared.call(&Request::Plan {
            root: root.to_path_buf(),
            targets: targets.to_vec(),
        })? {
            Reply::Plan(plan) => Ok(plan),
            other => Err(unexpected(&other)),
        }
    }

    /// Remove `plan`'s targets on the agent's machine. The agent plans
    /// them again itself and reports what its plan refuses as failed
    /// items, so nothing here can widen what it deletes.
    pub fn remove(&self, plan: &Plan, mode: RemovalMode) -> RemoteRemoval {
        let (id, replies) = self.shared.open(&Request::Remove {
            root: plan.root.clone(),
            targets: plan.targets.clone(),
            mode,
        });
        let (sender, events) = mpsc::channel();
        let worker = thread::Builder::new()
            .name(format!("disktree-remote-remove-{id}"))
            .spawn(move || forward_removal(&replies, &sender));
        drop(worker);
        RemoteRemoval {
            id,
            shared: Arc::clone(&self.shared),
            events,
        }
    }
}

impl Drop for Client {
    /// Closing stdin ends the agent's read loop; the kill covers an ssh
    /// that would linger. The reader thread then meets the end of output
    /// and fails whatever is still open.
    fn drop(&mut self) {
        drop(lock(&self.shared.stdin).take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Shared {
    /// Send `request` and return where its replies will arrive. Never
    /// fails: a request that cannot be sent gets its failure as a reply.
    fn open(&self, request: &Request) -> (u64, Receiver<Reply>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (sender, replies) = mpsc::channel();
        {
            let mut routes = lock(&self.routes);
            if let Some(reason) = &routes.closed {
                let _ = sender.send(lost(reason.clone()));
                return (id, replies);
            }
            routes.open.insert(id, sender);
        }
        if let Err(error) = self.write(id, request) {
            let reason = with_stderr(
                format!("could not reach the agent: {error}"),
                &self.stderr,
            );
            let sender = lock(&self.routes).open.remove(&id);
            if let Some(sender) = sender {
                let _ = sender.send(lost(reason));
            }
        }
        (id, replies)
    }

    /// Send `request` and wait for its one reply.
    fn call(&self, request: &Request) -> io::Result<Reply> {
        let (_, replies) = self.open(request);
        match replies.recv() {
            Ok(Reply::Failed { kind, message }) => {
                Err(io::Error::new(kind, message))
            }
            Ok(reply) => Ok(reply),
            Err(_) => Err(io::Error::other("the agent connection closed")),
        }
    }

    fn write(&self, id: u64, request: &Request) -> io::Result<()> {
        let (tag, payload) = request.encode(id);
        let mut frame = Vec::with_capacity(payload.len() + 11);
        crate::wire::write_frame(&mut frame, tag, &payload)?;
        let mut stdin = lock(&self.stdin);
        let pipe = stdin.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "the client was closed")
        })?;
        let written = pipe.write_all(&frame).and_then(|()| pipe.flush());
        drop(stdin);
        written
    }

    /// End the connection: every open request fails with `reason`, and
    /// so does every later one.
    fn close(&self, reason: String) {
        let mut routes = lock(&self.routes);
        for (_, sender) in routes.open.drain() {
            let _ = sender.send(lost(reason.clone()));
        }
        routes.closed = Some(reason);
    }
}

/// The reader thread: the handshake, then every reply to its request.
fn read_replies(
    stdout: impl Read,
    shared: &Shared,
    introduced: &Sender<io::Result<Hello>>,
    stderr_done: &Receiver<()>,
) {
    let mut stdout = BufReader::with_capacity(CHUNK, stdout);
    match handshake(&mut stdout) {
        Ok(hello) => {
            let _ = introduced.send(Ok(hello));
        }
        Err(error) => {
            // An agent that died or a shell that refused has said why on
            // stderr by the time its stdout closed; wait a moment for it.
            let _ = stderr_done.recv_timeout(Duration::from_millis(500));
            let message = with_stderr(error.to_string(), &shared.stderr);
            let _ = introduced.send(Err(io::Error::new(error.kind(), message)));
            return;
        }
    }
    let reason = loop {
        let (tag, payload) = match read_frame(&mut stdout) {
            Ok(Some(frame)) => frame,
            Ok(None) => break "the agent closed the connection".to_owned(),
            Err(error) => {
                break format!("the agent connection failed: {error}");
            }
        };
        let (id, reply) = match Reply::decode(tag, &payload) {
            Ok((id, Some(reply))) => (id, reply),
            // A newer agent's reply to nothing this client asked.
            Ok((_, None)) => continue,
            Err(error) => {
                break format!("the agent sent a broken reply: {error}");
            }
        };
        let last = reply.is_last();
        let mut routes = lock(&shared.routes);
        if let Some(sender) = routes.open.get(&id) {
            // A caller that stopped listening has moved on; the reply is
            // dropped with its channel.
            let _ = sender.send(reply);
        }
        if last {
            routes.open.remove(&id);
        }
    };
    let _ = stderr_done.recv_timeout(Duration::from_millis(500));
    shared.close(with_stderr(reason, &shared.stderr));
}

fn handshake(stdout: &mut impl Read) -> io::Result<Hello> {
    let protocol = read_preamble(stdout).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the agent exited before introducing itself",
            )
        } else {
            error
        }
    })?;
    if protocol != PROTOCOL {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "the agent speaks protocol {protocol} and this disktree \
                 speaks protocol {PROTOCOL}: they are from different \
                 releases, so install the matching agent"
            ),
        ));
    }
    match read_frame(stdout)? {
        Some((tag::HELLO, payload)) => Hello::decode(&payload, protocol),
        Some((other, _)) => {
            Err(invalid(format!("the agent began with message {other}")))
        }
        None => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the agent exited before introducing itself",
        )),
    }
}

/// Keep the last [`STDERR_TAIL`] bytes of `stderr`; the receiver hears
/// when it ends.
fn keep_tail(
    stderr: impl Read + Send + 'static,
    tail: Arc<Mutex<Vec<u8>>>,
) -> Receiver<()> {
    let (done, ended) = mpsc::channel();
    let _ = thread::Builder::new()
        .name("disktree-agent-stderr".into())
        .spawn(move || {
            let mut stderr = stderr;
            let mut buffer = [0_u8; 1024];
            while let Ok(read @ 1..) = stderr.read(&mut buffer) {
                let mut tail = lock(&tail);
                tail.extend_from_slice(&buffer[..read]);
                let excess = tail.len().saturating_sub(STDERR_TAIL);
                tail.drain(..excess);
            }
            let _ = done.send(());
        });
    ended
}

fn with_stderr(message: String, stderr: &Mutex<Vec<u8>>) -> String {
    let tail = String::from_utf8_lossy(&lock(stderr)).into_owned();
    let text = tail.trim();
    if text.is_empty() {
        message
    } else {
        format!("{message}: {text}")
    }
}

const fn lost(reason: String) -> Reply {
    Reply::Failed {
        kind: io::ErrorKind::BrokenPipe,
        message: reason,
    }
}

fn unexpected(reply: &Reply) -> io::Error {
    invalid(format!("the agent answered with {reply:?}"))
}

/// How a finished tree crossed the wire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Transfer {
    pub nodes: u64,
    /// Compressed bytes received.
    pub wire_bytes: u64,
    /// Bytes once decompressed.
    pub raw_bytes: u64,
    /// From the first chunk to the last node decoded.
    pub elapsed: Duration,
}

/// A scan running on the agent's machine; [`ScanHandle`] for a remote.
///
/// [`ScanHandle`]: disktree_core::scan::ScanHandle
#[derive(Debug)]
pub struct RemoteScan {
    id: u64,
    shared: Arc<Shared>,
    progress: Arc<Mutex<ScanSnapshot>>,
    result: Receiver<io::Result<Node>>,
    transfer: Arc<Mutex<Option<Transfer>>>,
}

impl RemoteScan {
    /// The counters the agent last reported.
    pub fn progress(&self) -> ScanSnapshot {
        lock(&self.progress).clone()
    }

    /// Take the finished tree, if it has arrived.
    pub fn poll(&self) -> Option<io::Result<Node>> {
        match self.result.try_recv() {
            Ok(outcome) => Some(outcome),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(Err(io::Error::other(
                "the remote scan stopped without a result",
            ))),
        }
    }

    /// Wait for the finished tree.
    pub fn wait(&self) -> io::Result<Node> {
        self.result.recv().unwrap_or_else(|_| {
            Err(io::Error::other("the remote scan stopped without a result"))
        })
    }

    /// Abandon the walk. Unlike a local cancel, no partial tree follows:
    /// [`Self::poll`] then reports [`io::ErrorKind::Interrupted`].
    pub fn cancel(&self) {
        lock(&self.progress).cancelled = true;
        let _ = self.shared.write(self.id, &Request::Cancel);
    }

    /// How the tree crossed the wire, once it has.
    pub fn transfer(&self) -> Option<Transfer> {
        *lock(&self.transfer)
    }
}

/// The scan worker: progress until the tree, then the tree.
fn receive_tree(
    replies: &Receiver<Reply>,
    progress: &Mutex<ScanSnapshot>,
    transfer: &Mutex<Option<Transfer>>,
) -> io::Result<Node> {
    let mut builder = TreeBuilder::new();
    let mut wire_bytes = 0;
    let mut raw_bytes = 0;
    let mut raw = Vec::with_capacity(CHUNK * 2);
    let mut started = None;
    loop {
        let reply = replies
            .recv()
            .map_err(|_| io::Error::other("the agent connection closed"))?;
        match reply {
            Reply::Progress(snapshot) => {
                let mut progress = lock(progress);
                // A cancel here wins over an agent that has not heard it.
                let cancelled = progress.cancelled;
                *progress = snapshot;
                progress.cancelled |= cancelled;
            }
            Reply::TreeChunk(chunk) => {
                started.get_or_insert_with(Instant::now);
                wire_bytes += chunk.len() as u64;
                raw.clear();
                let mut source = chunk.as_slice();
                StreamingDecoder::new(&mut source)
                    .map_err(|error| invalid(format!("a tree chunk: {error}")))?
                    // A chunk is cut at the first node boundary past CHUNK,
                    // so twice that is far more than any honest one.
                    .take((CHUNK * 4) as u64)
                    .read_to_end(&mut raw)?;
                builder.feed(&raw)?;
                raw_bytes += raw.len() as u64;
            }
            Reply::TreeEnd { nodes } => {
                if builder.nodes() != nodes {
                    return Err(invalid(format!(
                        "the agent sent {nodes} nodes and {} arrived",
                        builder.nodes()
                    )));
                }
                let tree = builder.finish()?;
                *lock(transfer) = Some(Transfer {
                    nodes,
                    wire_bytes,
                    raw_bytes,
                    elapsed: started.map_or(Duration::ZERO, |at| at.elapsed()),
                });
                return Ok(tree);
            }
            Reply::Failed { kind, message } => {
                return Err(io::Error::new(kind, message));
            }
            other => return Err(unexpected(&other)),
        }
    }
}

/// A removal running on the agent's machine; [`RemovalHandle`] for a
/// remote.
///
/// [`RemovalHandle`]: disktree_core::removal::RemovalHandle
#[derive(Debug)]
pub struct RemoteRemoval {
    id: u64,
    shared: Arc<Shared>,
    events: Receiver<RemovalEvent>,
}

impl RemoteRemoval {
    /// Take the next event, if one has arrived.
    pub fn poll(&self) -> Option<RemovalEvent> {
        self.events.try_recv().ok()
    }

    /// Wait for the next event; `None` after [`RemovalEvent::Done`].
    pub fn next(&self) -> Option<RemovalEvent> {
        self.events.recv().ok()
    }

    /// Stop before the next target starts.
    pub fn cancel(&self) {
        let _ = self.shared.write(self.id, &Request::Cancel);
    }
}

/// The removal worker: the agent's events as they come, and a lost
/// connection as one failed item and a `Done`, so the review screen
/// always reaches its end.
fn forward_removal(replies: &Receiver<Reply>, events: &Sender<RemovalEvent>) {
    let (mut removed, mut bytes, mut failed) = (0, 0, 0);
    for reply in replies {
        match reply {
            Reply::Removal(event) => {
                match &event {
                    RemovalEvent::Item {
                        bytes: size,
                        outcome,
                        ..
                    } => {
                        if outcome.is_ok() {
                            removed += 1;
                            bytes += size;
                        } else {
                            failed += 1;
                        }
                    }
                    RemovalEvent::Start { .. } => {}
                    RemovalEvent::Done { .. } => {
                        let _ = events.send(event);
                        return;
                    }
                }
                let _ = events.send(event);
            }
            other => {
                let message = match other {
                    Reply::Failed { message, .. } => message,
                    other => format!("the agent answered with {other:?}"),
                };
                let _ = events.send(RemovalEvent::Item {
                    path: std::path::PathBuf::new(),
                    bytes: 0,
                    outcome: Err(message),
                });
                let _ = events.send(RemovalEvent::Done {
                    removed,
                    bytes,
                    failed: failed + 1,
                });
                return;
            }
        }
    }
}

fn lock<T: ?Sized>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
