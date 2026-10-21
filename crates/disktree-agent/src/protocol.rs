//! The messages between a client and an agent.
//!
//! The agent speaks first, with its [`preamble`] and [`Hello`]. After that the client sends
//! requests, each with an id it chose, and the agent answers with replies
//! carrying that id: a scan's progress, its tree and a removal's events
//! arrive as several replies, everything else as one. Requests do not wait
//! for each other, so a free-space reading is answered while a scan runs.
//!
//! Tags below 32 go from the agent to the client; 32 and up the other way.
//! Every request payload starts with its id, so an agent that does not
//! know a tag can still say so to the right caller.

use std::io;
use std::path::PathBuf;

use disktree_core::removal::{
    Blocked, Plan, RemovalEvent, RemovalMode, Target, TrashBackend,
};
use disktree_core::scan::{ScanOptions, ScanSnapshot};
use disktree_core::scan_threads::ScanThreads;
use disktree_core::space::{Mount, SpaceInfo, Volume};
use disktree_core::tree::Metric;

use crate::wire::{Decoder, Encoder, invalid};

/// Bumped on any change to a message's layout; see [`preamble`].
pub const PROTOCOL: u32 = 1;

/// What an agent's output starts with: anything else on its stdout (a
/// login banner, a shell error) is not an agent.
pub const MAGIC: [u8; 4] = *b"DTAG";

pub mod tag {
    pub const HELLO: u8 = 1;
    pub const PROGRESS: u8 = 2;
    pub const TREE_CHUNK: u8 = 3;
    pub const TREE_END: u8 = 4;
    pub const FAILED: u8 = 5;
    pub const SPACE: u8 = 6;
    pub const PLAN: u8 = 7;
    pub const REMOVAL: u8 = 8;
    pub const VOLUMES: u8 = 9;
    /// Reserved for the repository state the app shows beside a tile.
    pub const GIT_STATE: u8 = 10;

    pub const SCAN: u8 = 32;
    pub const CANCEL: u8 = 33;
    pub const SPACE_OF: u8 = 34;
    pub const PLAN_FOR: u8 = 35;
    pub const REMOVE: u8 = 36;
    pub const LIST_VOLUMES: u8 = 37;
    /// Reserved: asks for [`GIT_STATE`].
    pub const GIT_STATE_OF: u8 = 38;
}

/// What an agent says about itself and its machine before anything else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    pub protocol: u32,
    /// The agent's crate version.
    pub version: String,
    /// `std::env::consts::ARCH`: `aarch64`, `x86_64`.
    pub arch: String,
    /// `std::env::consts::OS`.
    pub os: String,
    pub hostname: String,
    /// The home directory of the user the agent runs as.
    pub home: Option<PathBuf>,
    /// The mount table, as the scan and the removal guards read it there.
    pub mounts: Vec<Mount>,
    /// The volumes worth scanning, fullest first.
    pub volumes: Vec<Volume>,
    /// What moving to the trash would use there.
    pub trash: TrashBackend,
}

/// Free space where a path lives, and which volume that is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceReport {
    pub space: Result<SpaceInfo, String>,
    pub device: Option<String>,
    pub volume_root: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub enum Request {
    Scan {
        root: PathBuf,
        options: ScanOptions,
    },
    /// Stop the scan or removal with this id.
    Cancel,
    Space {
        path: PathBuf,
    },
    Plan {
        root: PathBuf,
        targets: Vec<Target>,
    },
    /// The agent plans `targets` itself and removes only what its plan
    /// allows.
    Remove {
        root: PathBuf,
        targets: Vec<Target>,
        mode: RemovalMode,
    },
    Volumes,
}

#[derive(Clone, Debug)]
pub enum Reply {
    Progress(ScanSnapshot),
    /// One zstd frame of the encoded tree.
    TreeChunk(Vec<u8>),
    /// The tree is complete; this many nodes were sent.
    TreeEnd {
        nodes: u64,
    },
    Failed {
        kind: io::ErrorKind,
        message: String,
    },
    Space(SpaceReport),
    Plan(Plan),
    Removal(RemovalEvent),
    Volumes(Vec<Volume>),
}

/// The first bytes an agent writes, before any frame: [`MAGIC`] and its
/// [`PROTOCOL`] number.
///
/// Fixed forever, so a client of any release can tell
/// a mismatch, and raw rather than framed, so a login banner or a shell's
/// error is refused after four bytes instead of read as a frame length.
pub fn preamble() -> Vec<u8> {
    let mut out = Encoder::new();
    out.buf.extend_from_slice(&MAGIC);
    out.uint(u64::from(PROTOCOL));
    out.buf
}

/// The protocol number from the front of an agent's output.
pub fn read_preamble(input: &mut impl io::Read) -> io::Result<u32> {
    let mut magic = [0_u8; MAGIC.len()];
    input.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(invalid(format!(
            "this is not a disktree agent: it began with {:?}",
            String::from_utf8_lossy(&magic)
        )));
    }
    let mut number = 0_u32;
    for shift in (0..32).step_by(7) {
        let mut byte = [0_u8];
        input.read_exact(&mut byte)?;
        number |= u32::from(byte[0] & 0x7F) << shift;
        if byte[0] & 0x80 == 0 {
            return Ok(number);
        }
    }
    Err(invalid("a protocol number longer than 32 bits"))
}

impl Hello {
    /// Everything but the protocol number, which the preamble carries.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Encoder::new();
        out.str(&self.version);
        out.str(&self.arch);
        out.str(&self.os);
        out.str(&self.hostname);
        out.option(self.home.as_deref(), Encoder::path);
        out.usize(self.mounts.len());
        for mount in &self.mounts {
            out.str(&mount.source);
            out.path(&mount.point);
            out.str(&mount.fstype);
            out.str(&mount.options);
        }
        put_volumes(&mut out, &self.volumes);
        out.u8(trash_code(self.trash));
        out.buf
    }

    pub fn decode(payload: &[u8], protocol: u32) -> io::Result<Self> {
        let mut input = Decoder::new(payload);
        let version = input.string()?;
        let arch = input.string()?;
        let os = input.string()?;
        let hostname = input.string()?;
        let home = input.option(Decoder::path)?;
        let mounts = (0..input.count()?)
            .map(|_| {
                Ok(Mount {
                    source: input.string()?,
                    point: input.path()?,
                    fstype: input.string()?,
                    options: input.string()?,
                })
            })
            .collect::<io::Result<_>>()?;
        let volumes = take_volumes(&mut input)?;
        let trash = trash_of(input.u8()?)?;
        Ok(Self {
            protocol,
            version,
            arch,
            os,
            hostname,
            home,
            mounts,
            volumes,
            trash,
        })
    }
}

impl Request {
    pub fn encode(&self, id: u64) -> (u8, Vec<u8>) {
        let mut out = Encoder::new();
        out.uint(id);
        let tag = match self {
            Self::Scan { root, options } => {
                out.path(root);
                put_options(&mut out, options);
                tag::SCAN
            }
            Self::Cancel => tag::CANCEL,
            Self::Space { path } => {
                out.path(path);
                tag::SPACE_OF
            }
            Self::Plan { root, targets } => {
                out.path(root);
                put_targets(&mut out, targets);
                tag::PLAN_FOR
            }
            Self::Remove {
                root,
                targets,
                mode,
            } => {
                out.path(root);
                put_targets(&mut out, targets);
                out.u8(match mode {
                    RemovalMode::Permanent => 0,
                    RemovalMode::Trash => 1,
                });
                tag::REMOVE
            }
            Self::Volumes => tag::LIST_VOLUMES,
        };
        (tag, out.buf)
    }

    /// The id, and the request when this agent knows its tag: an unknown
    /// one is answered with a failure, not a dropped connection.
    pub fn decode(tag: u8, payload: &[u8]) -> io::Result<(u64, Option<Self>)> {
        let mut input = Decoder::new(payload);
        let id = input.uint()?;
        let request = match tag {
            tag::SCAN => Self::Scan {
                root: input.path()?,
                options: take_options(&mut input)?,
            },
            tag::CANCEL => Self::Cancel,
            tag::SPACE_OF => Self::Space {
                path: input.path()?,
            },
            tag::PLAN_FOR => Self::Plan {
                root: input.path()?,
                targets: take_targets(&mut input)?,
            },
            tag::REMOVE => Self::Remove {
                root: input.path()?,
                targets: take_targets(&mut input)?,
                mode: match input.u8()? {
                    0 => RemovalMode::Permanent,
                    1 => RemovalMode::Trash,
                    other => {
                        return Err(invalid(format!("removal mode {other}")));
                    }
                },
            },
            tag::LIST_VOLUMES => Self::Volumes,
            _ => return Ok((id, None)),
        };
        Ok((id, Some(request)))
    }
}

impl Reply {
    /// Whether nothing more comes for this request after this reply.
    pub const fn is_last(&self) -> bool {
        match self {
            Self::Progress(_) | Self::TreeChunk(_) => false,
            Self::Removal(event) => {
                matches!(event, RemovalEvent::Done { .. })
            }
            Self::TreeEnd { .. }
            | Self::Failed { .. }
            | Self::Space(_)
            | Self::Plan(_)
            | Self::Volumes(_) => true,
        }
    }

    pub fn encode(&self, id: u64) -> (u8, Vec<u8>) {
        let mut out = Encoder::new();
        out.uint(id);
        let tag = match self {
            Self::Progress(snapshot) => {
                put_snapshot(&mut out, snapshot);
                tag::PROGRESS
            }
            Self::TreeChunk(chunk) => {
                out.buf.extend_from_slice(chunk);
                tag::TREE_CHUNK
            }
            Self::TreeEnd { nodes } => {
                out.uint(*nodes);
                tag::TREE_END
            }
            Self::Failed { kind, message } => {
                out.u8(kind_code(*kind));
                out.str(message);
                tag::FAILED
            }
            Self::Space(report) => {
                match &report.space {
                    Ok(space) => {
                        out.bool(true);
                        put_space(&mut out, *space);
                    }
                    Err(message) => {
                        out.bool(false);
                        out.str(message);
                    }
                }
                out.option(report.device.as_deref(), Encoder::str);
                out.option(report.volume_root.as_deref(), Encoder::path);
                tag::SPACE
            }
            Self::Plan(plan) => {
                put_targets(&mut out, &plan.targets);
                put_targets(&mut out, &plan.covered);
                out.usize(plan.blocked.len());
                for blocked in &plan.blocked {
                    out.path(&blocked.path);
                    out.str(&blocked.reason);
                }
                out.path(&plan.root);
                out.uint(plan.reclaim());
                out.uint(plan.foreign());
                tag::PLAN
            }
            Self::Removal(event) => {
                put_event(&mut out, event);
                tag::REMOVAL
            }
            Self::Volumes(volumes) => {
                put_volumes(&mut out, volumes);
                tag::VOLUMES
            }
        };
        (tag, out.buf)
    }

    /// The id, and the reply when this client knows its tag.
    pub fn decode(tag: u8, payload: &[u8]) -> io::Result<(u64, Option<Self>)> {
        let mut input = Decoder::new(payload);
        let id = input.uint()?;
        let reply = match tag {
            tag::PROGRESS => Self::Progress(take_snapshot(&mut input)?),
            tag::TREE_CHUNK => Self::TreeChunk(input.rest().to_vec()),
            tag::TREE_END => Self::TreeEnd {
                nodes: input.uint()?,
            },
            tag::FAILED => Self::Failed {
                kind: kind_of(input.u8()?),
                message: input.string()?,
            },
            tag::SPACE => Self::Space(SpaceReport {
                space: if input.bool()? {
                    Ok(take_space(&mut input)?)
                } else {
                    Err(input.string()?)
                },
                device: input.option(Decoder::string)?,
                volume_root: input.option(Decoder::path)?,
            }),
            tag::PLAN => {
                let targets = take_targets(&mut input)?;
                let covered = take_targets(&mut input)?;
                let blocked = (0..input.count()?)
                    .map(|_| {
                        Ok(Blocked {
                            path: input.path()?,
                            reason: input.string()?,
                        })
                    })
                    .collect::<io::Result<_>>()?;
                let root = input.path()?;
                let reclaim = input.uint()?;
                let foreign = input.uint()?;
                Self::Plan(Plan::from_parts(
                    targets, covered, blocked, root, reclaim, foreign,
                ))
            }
            tag::REMOVAL => Self::Removal(take_event(&mut input)?),
            tag::VOLUMES => Self::Volumes(take_volumes(&mut input)?),
            _ => return Ok((id, None)),
        };
        Ok((id, Some(reply)))
    }
}

fn put_options(out: &mut Encoder, options: &ScanOptions) {
    out.bool(options.apparent_size);
    out.bool(options.follow_links);
    out.bool(options.include_hidden);
    out.bool(options.one_filesystem);
    out.option(options.max_depth, Encoder::usize);
    out.bool(options.dedup_hardlinks);
    out.u8(match options.metric {
        Metric::Bytes => 0,
        Metric::Files => 1,
    });
    let threads = options.threads;
    out.usize(threads.max_threads);
    out.bool(threads.adaptive);
    out.f64(threads.retained_throughput);
    out.option(threads.system_cpu_limit, Encoder::f64);
}

fn take_options(input: &mut Decoder<'_>) -> io::Result<ScanOptions> {
    Ok(ScanOptions {
        apparent_size: input.bool()?,
        follow_links: input.bool()?,
        include_hidden: input.bool()?,
        one_filesystem: input.bool()?,
        max_depth: input.option(Decoder::usize)?,
        dedup_hardlinks: input.bool()?,
        metric: match input.u8()? {
            0 => Metric::Bytes,
            1 => Metric::Files,
            other => return Err(invalid(format!("metric {other}"))),
        },
        threads: ScanThreads {
            // Saturating: a 64-bit client's "no limit" is usize::MAX.
            max_threads: usize::try_from(input.uint()?).unwrap_or(usize::MAX),
            adaptive: input.bool()?,
            retained_throughput: input.f64()?,
            system_cpu_limit: input.option(Decoder::f64)?,
        },
    })
}

fn put_snapshot(out: &mut Encoder, snapshot: &ScanSnapshot) {
    out.uint(snapshot.files);
    out.uint(snapshot.dirs);
    out.uint(snapshot.bytes);
    out.uint(snapshot.errors);
    out.bool(snapshot.finished);
    out.bool(snapshot.cancelled);
    out.usize(snapshot.threads);
    out.bool(snapshot.threads_settled);
    out.bool(snapshot.thread_tuning_complete);
    out.bool(snapshot.system_cpu_limited);
    out.uint(snapshot.worker_transitions);
    out.usize(snapshot.messages.len());
    for message in &snapshot.messages {
        out.str(message);
    }
}

fn take_snapshot(input: &mut Decoder<'_>) -> io::Result<ScanSnapshot> {
    Ok(ScanSnapshot {
        files: input.uint()?,
        dirs: input.uint()?,
        bytes: input.uint()?,
        errors: input.uint()?,
        finished: input.bool()?,
        cancelled: input.bool()?,
        threads: input.usize()?,
        threads_settled: input.bool()?,
        thread_tuning_complete: input.bool()?,
        system_cpu_limited: input.bool()?,
        worker_transitions: input.uint()?,
        messages: (0..input.count()?)
            .map(|_| input.string())
            .collect::<io::Result<_>>()?,
    })
}

fn put_targets(out: &mut Encoder, targets: &[Target]) {
    out.usize(targets.len());
    for target in targets {
        out.path(&target.path);
        out.uint(target.bytes);
        out.bool(target.is_dir);
        out.bool(target.hidden);
    }
}

fn take_targets(input: &mut Decoder<'_>) -> io::Result<Vec<Target>> {
    (0..input.count()?)
        .map(|_| {
            Ok(Target {
                path: input.path()?,
                bytes: input.uint()?,
                is_dir: input.bool()?,
                hidden: input.bool()?,
            })
        })
        .collect()
}

fn put_space(out: &mut Encoder, space: SpaceInfo) {
    out.uint(space.total);
    out.uint(space.free);
    out.uint(space.available);
}

fn take_space(input: &mut Decoder<'_>) -> io::Result<SpaceInfo> {
    Ok(SpaceInfo {
        total: input.uint()?,
        free: input.uint()?,
        available: input.uint()?,
    })
}

fn put_volumes(out: &mut Encoder, volumes: &[Volume]) {
    out.usize(volumes.len());
    for volume in volumes {
        out.path(&volume.point);
        out.option(volume.device.as_deref(), Encoder::str);
        out.option(volume.space, put_space);
    }
}

fn take_volumes(input: &mut Decoder<'_>) -> io::Result<Vec<Volume>> {
    (0..input.count()?)
        .map(|_| {
            Ok(Volume {
                point: input.path()?,
                device: input.option(Decoder::string)?,
                space: input.option(take_space)?,
            })
        })
        .collect()
}

fn put_event(out: &mut Encoder, event: &RemovalEvent) {
    match event {
        RemovalEvent::Start { total } => {
            out.u8(0);
            out.usize(*total);
        }
        RemovalEvent::Item {
            path,
            bytes,
            outcome,
        } => {
            out.u8(1);
            out.path(path);
            out.uint(*bytes);
            out.option(outcome.as_ref().err(), |out, error| out.str(error));
        }
        RemovalEvent::Done {
            removed,
            bytes,
            failed,
        } => {
            out.u8(2);
            out.uint(*removed);
            out.uint(*bytes);
            out.usize(*failed);
        }
    }
}

fn take_event(input: &mut Decoder<'_>) -> io::Result<RemovalEvent> {
    Ok(match input.u8()? {
        0 => RemovalEvent::Start {
            total: input.usize()?,
        },
        1 => RemovalEvent::Item {
            path: input.path()?,
            bytes: input.uint()?,
            outcome: input.option(Decoder::string)?.map_or(Ok(()), Err),
        },
        2 => RemovalEvent::Done {
            removed: input.uint()?,
            bytes: input.uint()?,
            failed: input.usize()?,
        },
        other => return Err(invalid(format!("removal event {other}"))),
    })
}

const fn trash_code(backend: TrashBackend) -> u8 {
    match backend {
        TrashBackend::Unavailable => 0,
        TrashBackend::MacOs => 1,
        TrashBackend::TrashPut => 2,
        TrashBackend::Gio => 3,
        TrashBackend::XdgHome => 4,
        TrashBackend::RecycleBin => 5,
    }
}

fn trash_of(code: u8) -> io::Result<TrashBackend> {
    Ok(match code {
        0 => TrashBackend::Unavailable,
        1 => TrashBackend::MacOs,
        2 => TrashBackend::TrashPut,
        3 => TrashBackend::Gio,
        4 => TrashBackend::XdgHome,
        5 => TrashBackend::RecycleBin,
        other => return Err(invalid(format!("trash backend {other}"))),
    })
}

/// The kinds a caller may act on; the rest travel as their message.
const fn kind_code(kind: io::ErrorKind) -> u8 {
    match kind {
        io::ErrorKind::NotFound => 1,
        io::ErrorKind::PermissionDenied => 2,
        io::ErrorKind::Interrupted => 3,
        io::ErrorKind::InvalidInput => 4,
        io::ErrorKind::InvalidData => 5,
        io::ErrorKind::Unsupported => 6,
        _ => 0,
    }
}

const fn kind_of(code: u8) -> io::ErrorKind {
    match code {
        1 => io::ErrorKind::NotFound,
        2 => io::ErrorKind::PermissionDenied,
        3 => io::ErrorKind::Interrupted,
        4 => io::ErrorKind::InvalidInput,
        5 => io::ErrorKind::InvalidData,
        6 => io::ErrorKind::Unsupported,
        _ => io::ErrorKind::Other,
    }
}
