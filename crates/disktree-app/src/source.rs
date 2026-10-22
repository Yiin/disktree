//! Where the scanned disk is: the one door from the app to a filesystem.
//!
//! Every read of the disk being explored and every change to it goes through
//! [`Source`]: this machine's disk, or another's through its agent
//! ([`crate::remote`]). Methods take and return plain data, never a handle
//! that only works on this machine.
//!
//! What a source provides, `local only` marking what has no meaning for a
//! disk on another machine:
//!
//! * the scan: start one at a root, optionally reusing a known subtree
//!   ([`Source::scan`]); read its progress, take its tree, cancel it
//!   ([`SourceScan`]);
//! * free space, the mount source and the volume root of a path
//!   ([`Source::space`], [`Source::device`], [`Source::volume_root`]);
//! * the volumes the picker lists ([`Source::volumes_besides`]);
//! * the home directory, which the removal guards and `~` are about
//!   ([`Source::home`]);
//! * the root as given on the command line: canonical, and a directory
//!   ([`Source::canonical`], [`Source::is_dir`]);
//! * whether a path is still there ([`Source::exists`]);
//! * the removal plan, whose guards run where the disk is
//!   ([`Source::plan`]), and the removal itself ([`Source::remove`],
//!   [`SourceRemoval`]); which trash it uses ([`Source::trash_backend`]);
//! * whether a directory is a checkout, and what git knows about it
//!   ([`Source::is_checkout`], [`Source::git_state`]);
//! * the mount table primed before the first plan
//!   ([`Source::prime_mount_points`]);
//! * whether a whole NTFS drive can be read from its file table
//!   ([`Source::file_table_readable`]);
//! * local only: Full Disk Access and administrator rights, which are about
//!   this process ([`Source::full_disk_access`], [`Source::administrator`]),
//!   restarting as administrator, revealing a path in the file manager, and
//!   choosing a folder with the system picker. These check
//!   [`Source::is_local`].
//!
//! A remote source is connected before its first scan, off the UI thread
//! ([`Source::is_ready`], [`Source::connect`]); until then it answers as a
//! disk it cannot read.
//!
//! Desktop-side, not part of a source: the clipboard, the saved delete list
//! (a file the user picks on this machine), the power settings file and the
//! appearance settings.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use disktree_agent::{RemoteRemoval, RemoteScan};

use disktree_core::removal::{
    Plan, RemovalEvent, RemovalHandle, RemovalMode, Target, TrashBackend,
};
use disktree_core::scan::{Known, ScanHandle, ScanOptions, ScanSnapshot};
use disktree_core::space::{SpaceInfo, Volume};
use disktree_core::tree::Node;

use crate::remote::{Reach, Remote};
use disktree_core::git::GitState;

/// The machine whose disk is explored.
#[derive(Clone, Debug)]
pub enum Source {
    /// This machine, through `disktree-core` directly.
    Local,
    /// Another machine, through the agent there.
    Remote(Arc<Remote>),
}

impl Source {
    /// Whether the disk is this machine's, so a file manager, a folder
    /// picker or a restart here would act on it.
    pub const fn is_local(&self) -> bool {
        matches!(self, Self::Local)
    }

    /// The machine, as a notice names it.
    pub fn name(&self) -> &str {
        match self {
            Self::Local => "this machine",
            Self::Remote(remote) => &remote.host,
        }
    }

    /// The host a path is on, for a trail or title that names it; `None`
    /// for this machine, whose paths are written as they are.
    pub fn host(&self) -> Option<&str> {
        match self {
            Self::Local => None,
            Self::Remote(remote) => Some(&remote.host),
        }
    }

    /// The window title for `shown`, the directory on screen as displayed.
    pub fn title(&self, shown: &str) -> String {
        match self {
            Self::Local => format!("disktree · {shown}"),
            Self::Remote(remote) => {
                format!("disktree · {}:{shown}", remote.host)
            }
        }
    }

    /// Whether the disk can be read now. A remote source is not until it
    /// has connected, and again once its connection is lost.
    pub fn is_ready(&self) -> bool {
        match self {
            Self::Local => true,
            Self::Remote(remote) => remote.is_up(),
        }
    }

    /// Connect a remote source: reach the host, install the agent if it is
    /// missing, start it. Blocks; call it off the UI thread.
    pub fn connect(&self) -> Result<(), String> {
        match self {
            Self::Local => Ok(()),
            Self::Remote(remote) => remote.connect(),
        }
    }

    /// What connecting is doing, while it is: "Connecting to spark-1".
    pub fn stage(&self) -> Option<String> {
        match self {
            Self::Local => None,
            Self::Remote(remote) => remote.stage(),
        }
    }

    /// Why the connection to the disk ended, once it has.
    pub fn lost(&self) -> Option<String> {
        match self {
            Self::Local => None,
            Self::Remote(remote) => remote.lost(),
        }
    }

    /// The root to scan first, once connected, when the command line did
    /// not give this machine's: what it asked for, resolved there.
    pub fn first_root(&self) -> Result<PathBuf, String> {
        match self {
            Self::Local => std::env::home_dir()
                .ok_or_else(|| "no home directory".to_owned()),
            Self::Remote(remote) => remote.first_root(),
        }
    }

    /// The home directory of whoever the scan runs as; on another machine
    /// under `--sudo`, still the ssh user's.
    pub fn home(&self) -> Option<PathBuf> {
        match self {
            Self::Local => std::env::home_dir(),
            Self::Remote(remote) => remote.hello()?.home,
        }
    }

    /// `root` in the form a widening walk recognises again, or as given
    /// when it cannot be resolved. Through dunce, so Windows gets
    /// `C:\Users\…` rather than the `\\?\C:\…` form nothing else is written
    /// in.
    pub fn canonical(&self, root: PathBuf) -> PathBuf {
        match self {
            Self::Local => dunce::canonicalize(&root).unwrap_or(root),
            Self::Remote(remote) => remote
                .path_info(&root)
                .ok()
                .and_then(|info| info.canonical)
                .unwrap_or(root),
        }
    }

    /// Whether `path` is a directory, following links.
    pub fn is_dir(&self, path: &Path) -> io::Result<bool> {
        match self {
            Self::Local => Ok(std::fs::metadata(path)?.is_dir()),
            Self::Remote(remote) => remote
                .path_info(path)
                .and_then(|info| info.is_dir)
                .map_err(io::Error::other),
        }
    }

    /// Whether anything is at `path`, without following a link.
    pub fn exists(&self, path: &Path) -> bool {
        match self {
            Self::Local => std::fs::symlink_metadata(path).is_ok(),
            Self::Remote(remote) => {
                remote.path_info(path).is_ok_and(|info| info.exists)
            }
        }
    }

    /// Whether `node`, the directory at `path`, is the top of a checkout.
    /// There, from the tree: a `.git` among its entries. A tree scanned
    /// without hidden entries has none to show.
    pub fn is_checkout(&self, path: &Path, node: &Node) -> bool {
        match self {
            Self::Local => disktree_core::git::is_checkout(path),
            Self::Remote(_) => node.child_named(".git").is_some(),
        }
    }

    /// Start walking `root`, reusing `known` where the walk reaches it.
    pub fn scan(
        &self,
        root: PathBuf,
        options: ScanOptions,
        known: Option<Known>,
    ) -> SourceScan {
        match self {
            Self::Local => {
                SourceScan::Local(ScanHandle::spawn_with(root, options, known))
            }
            // The agent walks the wider root whole; reusing what is known
            // there is dt-lo9.8.
            Self::Remote(remote) => match remote.client() {
                Some(client) => {
                    SourceScan::Remote(client.scan(&root, &options))
                }
                None => SourceScan::Unreachable(format!(
                    "not connected to {}",
                    remote.host
                )),
            },
        }
    }

    /// Free space on the volume holding `path`, `None` when unreadable.
    /// On another machine, the last reading, while the next is asked for.
    pub fn space(&self, path: &Path) -> Option<SpaceInfo> {
        match self {
            Self::Local => disktree_core::space::space_info(path).ok(),
            Self::Remote(remote) => remote.report(path)?.space.ok(),
        }
    }

    /// The device `path` is mounted from.
    pub fn device(&self, path: &Path) -> Option<String> {
        match self {
            Self::Local => disktree_core::space::device_for(path),
            Self::Remote(remote) => remote.report(path)?.device,
        }
    }

    /// The top of the volume `path` lives on: what "Whole disk" scans.
    pub fn volume_root(&self, path: &Path) -> Option<PathBuf> {
        match self {
            Self::Local => disktree_core::space::volume_root_for(path),
            Self::Remote(remote) => remote.report(path)?.volume_root,
        }
    }

    /// Every volume the picker offers while `root` is scanned: the mounted
    /// volumes, plus the one holding `root` when the table missed it, less
    /// `root` itself. Slow on removable and network media; call it off the
    /// UI thread.
    pub fn volumes_besides(&self, root: &Path) -> Vec<Volume> {
        let mut volumes = match self {
            Self::Local => disktree_core::space::volumes(),
            Self::Remote(remote) => remote
                .client()
                .and_then(|client| client.volumes().ok())
                .unwrap_or_default(),
        };
        if let Some(point) = self.volume_root(root)
            && !volumes.iter().any(|volume| volume.point == point)
        {
            volumes.push(Volume {
                device: self.device(&point),
                space: self.space(&point),
                point,
            });
        }
        volumes.retain(|volume| volume.point != root);
        volumes
    }

    /// Whether `root` is a whole NTFS drive an administrator reads from its
    /// file table. `false` off Windows.
    #[allow(
        clippy::missing_const_for_fn,
        reason = "const only where the core stub is; Windows asks the system"
    )]
    pub fn file_table_readable(&self, root: &Path) -> bool {
        match self {
            Self::Local => disktree_core::access::file_table_readable(root),
            Self::Remote(_) => false,
        }
    }

    /// Read the mount table now, so the first plan does not wait on it.
    /// An agent does that itself as it starts.
    pub fn prime_mount_points(&self) {
        match self {
            Self::Local => disktree_core::removal::prime_mount_points(),
            Self::Remote(_) => {}
        }
    }

    /// The trash removals in trash mode go to.
    pub fn trash_backend(&self) -> TrashBackend {
        match self {
            Self::Local => disktree_core::removal::detect_trash_backend(),
            Self::Remote(remote) => remote.trash_backend(),
        }
    }

    /// Why trash mode is off, where the reason is not the machine's lack
    /// of a trash tool: under `--sudo` it would fill the user's trash with
    /// root's entries.
    pub fn trash_off(&self) -> Option<&'static str> {
        match self {
            Self::Remote(remote)
                if matches!(remote.reach, Reach::Ssh { sudo: true }) =>
            {
                Some(
                    "No trash under --sudo: root's entries in your trash \
                     would need root to empty.",
                )
            }
            _ => None,
        }
    }

    /// What removing `targets` under `root` would do, with every guard
    /// applied where the disk is.
    pub fn plan(&self, targets: &[Target], root: &Path) -> Plan {
        match self {
            Self::Local => disktree_core::removal::plan(targets, root),
            Self::Remote(remote) => remote.plan(targets, root),
        }
    }

    /// Carry out `plan` on a worker. On another machine the agent plans
    /// the targets again and removes only what its own plan allows.
    pub fn remove(&self, plan: Plan, mode: RemovalMode) -> SourceRemoval {
        match self {
            Self::Local => {
                SourceRemoval::Local(disktree_core::removal::spawn(plan, mode))
            }
            Self::Remote(remote) => match remote.client() {
                Some(client) => {
                    SourceRemoval::Remote(client.remove(&plan, mode))
                }
                None => {
                    SourceRemoval::Unreachable(std::sync::Mutex::new(vec![
                        RemovalEvent::Done {
                            removed: 0,
                            bytes: 0,
                            failed: plan.targets.len(),
                        },
                        RemovalEvent::Item {
                            path: plan.root,
                            bytes: 0,
                            outcome: Err(format!(
                                "not connected to {}",
                                remote.host
                            )),
                        },
                    ]))
                }
            },
        }
    }

    /// What git knows about `path`, `None` when it is not a checkout or
    /// cannot be asked.
    pub fn git_state(&self, path: &Path) -> Option<GitState> {
        match self {
            Self::Local => disktree_core::git::state(path),
            Self::Remote(remote) => remote.client()?.git_state(path).ok()?,
        }
    }

    /// Whether macOS lets this process read everything under `home`.
    /// Local only: `None` off macOS and for another machine.
    pub fn full_disk_access(&self, home: &Path) -> Option<bool> {
        match self {
            Self::Local => disktree_core::access::full_disk_access(home),
            Self::Remote(_) => None,
        }
    }

    /// Whether this process is an administrator. Local only: `None` off
    /// Windows and for another machine.
    #[allow(
        clippy::missing_const_for_fn,
        reason = "const only where the core stub is; Windows asks the system"
    )]
    pub fn administrator(&self) -> Option<bool> {
        match self {
            Self::Local => disktree_core::access::administrator(),
            Self::Remote(_) => None,
        }
    }
}

/// A scan in flight, wherever it runs.
#[derive(Debug)]
pub enum SourceScan {
    Local(ScanHandle),
    Remote(RemoteScan),
    /// One that could not start, and why.
    Unreachable(String),
}

impl SourceScan {
    /// The counters as they stand.
    pub fn progress(&self) -> ScanSnapshot {
        match self {
            Self::Local(scan) => scan.progress.snapshot(),
            Self::Remote(scan) => scan.progress(),
            Self::Unreachable(_) => ScanSnapshot::default(),
        }
    }

    /// Take the finished tree, if the walk is done.
    pub fn poll(&self) -> Option<io::Result<Node>> {
        match self {
            Self::Local(scan) => scan.poll(),
            Self::Remote(scan) => scan.poll(),
            Self::Unreachable(reason) => {
                Some(Err(io::Error::other(reason.clone())))
            }
        }
    }

    /// Abandon the walk.
    pub fn cancel(&self) {
        match self {
            Self::Local(scan) => scan.cancel(),
            Self::Remote(scan) => scan.cancel(),
            Self::Unreachable(_) => {}
        }
    }
}

/// A removal in flight, wherever it runs.
#[derive(Debug)]
pub enum SourceRemoval {
    Local(RemovalHandle),
    Remote(RemoteRemoval),
    /// One that could not start: its events, last first.
    Unreachable(std::sync::Mutex<Vec<RemovalEvent>>),
}

impl SourceRemoval {
    /// Take the next event, if one has arrived.
    pub fn poll(&self) -> Option<RemovalEvent> {
        match self {
            Self::Local(run) => run.poll(),
            Self::Remote(run) => run.poll(),
            Self::Unreachable(events) => events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop(),
        }
    }

    /// Stop after the item in progress.
    pub fn cancel(&self) {
        match self {
            Self::Local(run) => run.cancel(),
            Self::Remote(run) => run.cancel(),
            Self::Unreachable(_) => {}
        }
    }
}
