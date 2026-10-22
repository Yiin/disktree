//! Another machine's disk, through `disktree-agent` on that machine.
//!
//! `disktree spark-1` reaches the host the way `ssh spark-1` does, with
//! the user's own ssh config: one probe says what the machine is and which
//! agents it has, the agent this build carries for its architecture is
//! copied to `~/.cache/disktree/agent-<hash>` there if missing, and one
//! long-lived `ssh -T spark-1 … serve` carries every request for the
//! session. The agent runs the scan, the free-space readings and the
//! removal guards on its own machine.
//!
//! The screens read a source on the UI thread, and a link can hang, so
//! nothing the screens call waits on the agent: free space is answered
//! from the last reading while the next one is asked for, and a plan is
//! asked once per set of marks, "checking" until it lands. Each ask runs
//! on a thread of its own, with the client's deadline, and every answer
//! that lands bumps [`Remote::answers`] so the window knows to redraw.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use disktree_agent::{Client, Hello, PathInfo, SpaceReport};
use disktree_core::removal::{Blocked, Plan, Target, TrashBackend};

/// Where the agent is installed, under the remote home directory.
const AGENT_DIR: &str = ".cache/disktree";

/// How often a path's free space is asked for again. The screens ask on
/// every tick; the agent is asked at most this often.
const REFRESH: Duration = Duration::from_secs(1);

/// How long a plan that could not be asked stands before it is asked
/// again. Not cached past that: the next look at the review screen, or
/// the next Delete, asks again.
const RETRY: Duration = Duration::from_secs(2);

/// What a target is kept back for while the agent judges it.
const CHECKING: &str = "checking on ";

use disktree_core::space::SPARKOS_DISK;

/// What the command line asked to scan there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ask {
    /// The real disk on `SparkOS`, else the home directory.
    Default,
    /// `-D`: the whole volume the home directory is on.
    Disk,
    /// A path; one that is relative is taken from the home directory, as
    /// scp does.
    Path(PathBuf),
}

/// How the agent is started.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reach {
    /// Over ssh, installing the agent first; under `sudo -n` when asked.
    Ssh { sudo: bool },
    /// An agent binary on this machine, run as it is: the tests' stand-in
    /// for a host, with the real protocol and none of ssh.
    #[cfg_attr(not(test), allow(dead_code, reason = "the tests' remote"))]
    Direct(PathBuf),
}

/// One host, and the connection to its agent once there is one.
#[derive(Debug)]
pub struct Remote {
    /// The host as the user named it, as ssh is given it and as every
    /// message, the title and the trail name it.
    pub host: String,
    pub reach: Reach,
    pub ask: Ask,
    /// The host was a bare word on the command line, a host only because
    /// no local path has that name: an ssh that cannot resolve it says
    /// so in those terms.
    pub bare: bool,
    link: Mutex<Link>,
    /// What connecting is doing now, for the scanning screen.
    stage: Mutex<Option<String>>,
    reports: Arc<Mutex<HashMap<PathBuf, Report>>>,
    plan: Arc<Mutex<PlanCache>>,
    /// Bumped each time an answer lands, so the window knows to redraw.
    answers: Arc<AtomicU64>,
}

#[derive(Debug, Default)]
struct Link {
    /// The connection, kept after it is lost: a request on it then fails
    /// at once with the reason, which is what the screens should show.
    connection: Option<Arc<Client>>,
    /// Bumped per connection, so a plan from the last one is not taken
    /// for this one's.
    generation: u64,
}

/// The last free-space reading of a path, and whether the next is asked.
#[derive(Debug, Default)]
struct Report {
    value: Option<SpaceReport>,
    asking: bool,
    asked: Option<Instant>,
}

/// The plan for the last set of marks asked about.
#[derive(Debug, Default)]
struct PlanCache {
    key: Option<PlanKey>,
    state: PlanState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PlanKey {
    generation: u64,
    root: PathBuf,
    targets: Vec<Target>,
}

#[derive(Debug, Default)]
enum PlanState {
    #[default]
    Asking,
    Answered(Plan),
    /// Why it could not be asked, and when: kept for [`RETRY`] only.
    Failed {
        reason: String,
        at: Instant,
    },
}

impl Remote {
    pub fn new(host: String, reach: Reach, ask: Ask) -> Self {
        Self {
            host,
            reach,
            ask,
            bare: false,
            link: Mutex::new(Link::default()),
            stage: Mutex::new(None),
            reports: Arc::new(Mutex::new(HashMap::new())),
            plan: Arc::new(Mutex::new(PlanCache::default())),
            answers: Arc::new(AtomicU64::new(0)),
        }
    }

    /// How many answers have landed: when it changes, what the screens
    /// read from here may have too.
    pub fn answers(&self) -> u64 {
        self.answers.load(Ordering::Relaxed)
    }

    /// The agent's client: connected, or lost and failing every request.
    pub fn client(&self) -> Option<Arc<Client>> {
        lock(&self.link).connection.clone()
    }

    /// Whether there is a connection that has not been lost.
    pub fn is_up(&self) -> bool {
        self.client()
            .is_some_and(|client| client.closed().is_none())
    }

    /// Why the connection ended, once it has.
    pub fn lost(&self) -> Option<String> {
        self.client()?.closed()
    }

    /// What connecting is doing, while it is.
    pub fn stage(&self) -> Option<String> {
        lock(&self.stage).clone()
    }

    fn set_stage(&self, stage: String) {
        *lock(&self.stage) = Some(stage);
    }

    pub fn hello(&self) -> Option<Hello> {
        self.client().map(|client| client.hello().clone())
    }

    /// The trash removals there go to: none under `--sudo`; see
    /// [`trash_offered`].
    pub fn trash_backend(&self) -> TrashBackend {
        trash_offered(&self.reach, self.hello().as_ref())
    }

    /// Reach the host, install the agent if it is missing, and start it.
    /// Blocks: call it off the UI thread.
    pub fn connect(&self) -> Result<(), String> {
        let started = self.start();
        *lock(&self.stage) = None;
        let client = started?;
        let mut link = lock(&self.link);
        link.generation += 1;
        link.connection = Some(Arc::new(client));
        drop(link);
        lock(&self.reports).clear();
        Ok(())
    }

    fn start(&self) -> Result<Client, String> {
        let host = &self.host;
        match &self.reach {
            Reach::Direct(agent) => {
                self.set_stage(format!("Starting the agent for {host}"));
                let mut command = Command::new(agent);
                command.arg("serve");
                Client::connect(command)
                    .map_err(|error| format!("{host}: {error}"))
            }
            Reach::Ssh { sudo } => {
                let shell = Shell::Ssh { host: host.clone() };
                self.set_stage(format!("Connecting to {host}"));
                connect_installed(&shell, embedded, *sudo, |stage| {
                    self.set_stage(match stage {
                        Stage::Installing => {
                            format!("Installing the agent on {host}")
                        }
                        Stage::Starting => {
                            format!("Starting the agent on {host}")
                        }
                    });
                })
                .map_err(|failure| match failure {
                    Failure::Install(error) => self.unreachable(&error),
                    Failure::Start(error) => explain(host, *sudo, &error),
                })
            }
        }
    }

    /// A failure to reach the host, said for what the user typed: a bare
    /// word ssh cannot resolve was most likely a local path mistyped.
    fn unreachable(&self, error: &str) -> String {
        if self.bare && error.contains("Could not resolve hostname") {
            format!("no local path or ssh host named {}", self.host)
        } else {
            format!("{}: {error}", self.host)
        }
    }

    /// The root the command line asked for, now that the host has said
    /// what it is.
    pub fn first_root(&self) -> Result<PathBuf, String> {
        let hello = self
            .hello()
            .ok_or_else(|| format!("not connected to {}", self.host))?;
        first_root(&self.ask, &hello)
            .ok_or_else(|| format!("{} reports no home directory", self.host))
    }

    /// What is at `path` there, or why that could not be asked. Blocks
    /// up to the client's deadline: call it off the UI thread.
    pub fn path_info(&self, path: &Path) -> Result<PathInfo, String> {
        let client = self
            .client()
            .ok_or_else(|| format!("not connected to {}", self.host))?;
        client.path_info(path).map_err(|error| error.to_string())
    }

    /// The last free-space reading of `path`, asking for the next one
    /// when the last is older than [`REFRESH`]. Never waits: `None` until
    /// the first reading lands.
    pub fn report(&self, path: &Path) -> Option<SpaceReport> {
        let client = self.client()?;
        let mut reports = lock(&self.reports);
        let report = reports.entry(path.to_path_buf()).or_default();
        let known = report.value.clone();
        if report.asking
            || report.asked.is_some_and(|at| at.elapsed() < REFRESH)
        {
            return known;
        }
        report.asking = true;
        report.asked = Some(Instant::now());
        drop(reports);
        let reports = Arc::clone(&self.reports);
        let answers = Arc::clone(&self.answers);
        let path = path.to_path_buf();
        let spawned = thread::Builder::new()
            .name("disktree-remote-space".into())
            .spawn({
                let path = path.clone();
                move || {
                    let value = client.space(&path).ok();
                    let mut reports = lock(&reports);
                    let report = reports.entry(path).or_default();
                    report.asking = false;
                    let changed = value.is_some() && report.value != value;
                    if changed {
                        report.value = value;
                    }
                    drop(reports);
                    if changed {
                        answers.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        if spawned.is_err() {
            lock(&self.reports).entry(path).or_default().asking = false;
        }
        known
    }

    /// The agent's plan for `targets`, asked once per set of marks. Never
    /// waits: until the answer lands, and when it cannot be asked, every
    /// target is kept back with the reason, since a plan nobody judged
    /// removes nothing. Only an answer is kept; a failure is asked again
    /// after [`RETRY`]. A lost connection keeps no answer: a Delete on it
    /// could only fail, so the review says why before it is pressed.
    pub fn plan(&self, targets: &[Target], root: &Path) -> Plan {
        let link = lock(&self.link);
        let generation = link.generation;
        let client = link.connection.clone();
        drop(link);
        let Some(client) = client.filter(|client| client.closed().is_none())
        else {
            let reason = format!("not connected to {}", self.host);
            return refuse_all(targets, root, &reason);
        };
        let key = PlanKey {
            generation,
            root: root.to_path_buf(),
            targets: targets.to_vec(),
        };
        let mut cache = lock(&self.plan);
        if cache.key.as_ref() == Some(&key) {
            match &cache.state {
                PlanState::Answered(plan) => return plan.clone(),
                PlanState::Asking => {
                    return refuse_all(targets, root, &self.checking());
                }
                PlanState::Failed { reason, at } if at.elapsed() < RETRY => {
                    return refuse_all(targets, root, reason);
                }
                PlanState::Failed { .. } => {}
            }
        }
        cache.key = Some(key.clone());
        cache.state = PlanState::Asking;
        drop(cache);

        let cache = Arc::clone(&self.plan);
        let answers = Arc::clone(&self.answers);
        let host = self.host.clone();
        let spawned = thread::Builder::new()
            .name("disktree-remote-plan".into())
            .spawn(move || {
                let state = match client.plan(&key.targets, &key.root) {
                    Ok(plan) => PlanState::Answered(plan),
                    Err(error) => PlanState::Failed {
                        reason: format!("{host} could not judge it: {error}"),
                        at: Instant::now(),
                    },
                };
                let mut cache = lock(&cache);
                // Marks changed meanwhile: that set has an ask of its own.
                if cache.key.as_ref() == Some(&key) {
                    cache.state = state;
                }
                drop(cache);
                answers.fetch_add(1, Ordering::Relaxed);
            });
        if let Err(error) = spawned {
            let reason = format!("could not ask {}: {error}", self.host);
            lock(&self.plan).state = PlanState::Failed {
                reason: reason.clone(),
                at: Instant::now(),
            };
            return refuse_all(targets, root, &reason);
        }
        refuse_all(targets, root, &self.checking())
    }

    fn checking(&self) -> String {
        format!("{CHECKING}{}", self.host)
    }
}

/// Whether `plan` is still waiting for the agent's answer.
#[cfg_attr(not(test), allow(dead_code, reason = "the tests wait on it"))]
pub fn is_checking(plan: &Plan) -> bool {
    plan.blocked
        .iter()
        .any(|blocked| blocked.reason.starts_with(CHECKING))
}

/// [`Remote::first_root`] for a host that said `hello`; `None` when the
/// answer needs a home directory it has none of.
fn first_root(ask: &Ask, hello: &Hello) -> Option<PathBuf> {
    let home = || hello.home.clone();
    Some(match ask {
        Ask::Default => {
            let sparkos = hello
                .mounts
                .iter()
                .any(|mount| mount.point == Path::new(SPARKOS_DISK));
            if sparkos {
                PathBuf::from(SPARKOS_DISK)
            } else {
                home()?
            }
        }
        Ask::Disk => disk_of(&hello.mounts, &home()?),
        // `~` and `~/x`, as scp reads them: the home directory there.
        Ask::Path(path) if path.starts_with("~") => {
            let rest = path.strip_prefix("~").ok()?;
            let home = home()?;
            if rest.as_os_str().is_empty() {
                home
            } else {
                home.join(rest)
            }
        }
        Ask::Path(path) if path.is_relative() => home()?.join(path),
        Ask::Path(path) => path.clone(),
    })
}

/// Whether `path` starts at another user's home, `~user`, as scp reads
/// it. Refused on the command line: the agent would have to look the
/// user up, and taken as a plain name it would be a folder in one's own
/// home.
pub fn names_a_user(path: &Path) -> bool {
    match path.components().next() {
        Some(std::path::Component::Normal(first)) => {
            first != "~" && first.to_string_lossy().starts_with('~')
        }
        _ => false,
    }
}

/// The whole disk `home` is on, as `-D` scans it. On `SparkOS` that is
/// [`SPARKOS_DISK`]: `/home` is a bind of a folder on it, and the mounts
/// above home show only the bind.
fn disk_of(mounts: &[disktree_core::space::Mount], home: &Path) -> PathBuf {
    let own = mounts
        .iter()
        .filter(|mount| home.starts_with(&mount.point))
        .max_by_key(|mount| mount.point.as_os_str().len());
    let sparkos = mounts
        .iter()
        .find(|mount| mount.point == Path::new(SPARKOS_DISK));
    if let (Some(own), Some(disk)) = (own, sparkos)
        && own.source == disk.source
    {
        return PathBuf::from(SPARKOS_DISK);
    }
    disktree_core::space::volume_root(mounts, home)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// A plan in which every target is kept back for `reason`.
fn refuse_all(targets: &[Target], root: &Path, reason: &str) -> Plan {
    let blocked = targets
        .iter()
        .map(|target| Blocked {
            path: target.path.clone(),
            reason: reason.to_owned(),
        })
        .collect();
    Plan::from_parts(Vec::new(), Vec::new(), blocked, root.to_path_buf(), 0, 0)
}

/// A failed start, said in terms of what to do about it.
fn explain(host: &str, sudo: bool, error: &io::Error) -> String {
    let message = error.to_string();
    if sudo && message.contains("password is required") {
        return format!(
            "{host}: sudo there asks for a password, and disktree never \
             prompts for one. Allow it without one (NOPASSWD), or leave \
             out --sudo"
        );
    }
    format!("{host}: {message}")
}

// ── installing the agent ────────────────────────────────────────────────

/// A POSIX shell on the machine the agent goes to.
#[derive(Clone, Debug)]
pub enum Shell {
    /// `ssh -T host sh -c '…'`, with the user's ssh config.
    Ssh { host: String },
    /// `sh -c '…'` here, with `HOME` set: the tests' stand-in for a host.
    #[cfg_attr(not(test), allow(dead_code, reason = "the tests' remote"))]
    Local { home: PathBuf },
}

impl Shell {
    /// A command that runs `script` there. The script is passed as one
    /// single-quoted word through whatever login shell the account has,
    /// so it holds no single quote of its own.
    pub fn command(&self, script: &str) -> Command {
        assert!(!script.contains('\''), "a script with a single quote");
        match self {
            Self::Ssh { host } => {
                let mut command = Command::new("ssh");
                command.args([
                    "-T",
                    // Fail instead of asking for a password or a host key:
                    // nobody is at a terminal to answer.
                    "-o",
                    "BatchMode=yes",
                    // A link that drops without a word is noticed within
                    // 15 s instead of hanging every request on it.
                    "-o",
                    "ServerAliveInterval=5",
                    "-o",
                    "ServerAliveCountMax=3",
                    "--",
                    host,
                    "sh",
                    "-c",
                    &format!("'{script}'"),
                ]);
                command
            }
            Self::Local { home } => {
                let mut command = Command::new("sh");
                command.args(["-c", script]).env("HOME", home);
                command
            }
        }
    }

    /// Run `script`, any number of lines, with `payload` on its stdin
    /// after it. The command line only reads the script, exactly, with
    /// `dd`, and hands it to `sh`: a login shell such as csh cannot take a
    /// quoted word over several lines, and `sh -s` is no way round it,
    /// since busybox's reads ahead into the payload.
    fn run_script(
        &self,
        script: &str,
        payload: &[u8],
    ) -> Result<String, String> {
        let reader =
            format!("eval \"$(dd bs=1 count={} 2>/dev/null)\"", script.len());
        let mut input = script.as_bytes().to_vec();
        input.extend_from_slice(payload);
        self.run(&reader, &input)
    }

    /// Run `script` with `input` on its stdin, and return its stdout.
    fn run(&self, script: &str, input: &[u8]) -> Result<String, String> {
        let mut child = self
            .command(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("could not start ssh: {error}"))?;
        // Fed from a thread: a script that fails early stops reading, and
        // its stderr must still be read meanwhile.
        let mut stdin = child.stdin.take();
        let input = input.to_vec();
        let feeder = thread::spawn(move || {
            if let Some(stdin) = stdin.as_mut() {
                let _ = stdin.write_all(&input);
            }
        });
        let output = child
            .wait_with_output()
            .map_err(|error| format!("ssh failed: {error}"))?;
        let _ = feeder.join();
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(match stderr.trim() {
                "" => format!("the shell there exited with {}", output.status),
                text => text.to_owned(),
            })
        }
    }
}

/// What installing is doing, for the scanning screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Copying the agent there: it was missing or another release's.
    Installing,
    Starting,
}

/// The agent this build carries for `arch`, as `uname -m` names it.
#[allow(
    clippy::missing_const_for_fn,
    reason = "const only in a build that carries no agent"
)]
pub fn embedded(arch: &str) -> Option<&'static [u8]> {
    #[cfg(agent_aarch64)]
    if arch == "aarch64" {
        return Some(include_bytes!(env!("DISKTREE_AGENT_AARCH64")));
    }
    #[cfg(agent_x86_64)]
    if arch == "x86_64" {
        return Some(include_bytes!(env!("DISKTREE_AGENT_X86_64")));
    }
    let _ = arch;
    None
}

/// The agent's file name there: its content's hash, so a host keeps the
/// one agent each release needs and never runs a stale one.
pub fn agent_name(agent: &[u8]) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(agent);
    let mut name = String::from("agent-");
    for byte in &digest[..8] {
        let _ = write!(name, "{byte:02x}");
    }
    name
}

/// What the probe found there.
#[derive(Debug, PartialEq, Eq)]
struct Probe {
    arch: String,
    /// The agents in the agent folder.
    present: Vec<String>,
}

/// One round trip: the machine, and which agents it has. Each answer is
/// on a line of its own with a mark, so whatever else a login shell
/// prints is passed over.
const PROBE: &str = "echo \"arch=$(uname -m)\"; for f in \
                     \"$HOME/.cache/disktree\"/agent-*; do \
                     echo \"have=${f##*/}\"; done; exit 0";

fn parse_probe(output: &str) -> Option<Probe> {
    let arch = output
        .lines()
        .filter_map(|line| line.strip_prefix("arch="))
        .next_back()?;
    let arch = match arch.trim() {
        // macOS and some BSDs say arm64; Debian's tools say amd64.
        "arm64" => "aarch64",
        "amd64" => "x86_64",
        other => other,
    }
    .to_owned();
    Some(Probe {
        arch,
        present: output
            .lines()
            .filter_map(|line| line.strip_prefix("have="))
            .map(str::to_owned)
            .collect(),
    })
}

/// Why connecting failed: on the way to the agent, or starting it.
#[derive(Debug)]
pub enum Failure {
    Install(String),
    Start(io::Error),
}

/// Install the agent if it is missing, and start it, under `sudo -n` when
/// asked. An agent the probe saw but that is gone when it is started,
/// which another disktree's cleanup can do, is installed again, once.
pub fn connect_installed(
    shell: &Shell,
    agents: impl Fn(&str) -> Option<&'static [u8]>,
    sudo: bool,
    mut stage: impl FnMut(Stage),
) -> Result<Client, Failure> {
    let agent = install_with(shell, &agents, false, &mut stage)
        .map_err(Failure::Install)?;
    match Client::connect(shell.command(&serve_script(&agent, sudo))) {
        Err(error) if vanished(&error, &agent) => {
            let agent = install_with(shell, &agents, true, &mut stage)
                .map_err(Failure::Install)?;
            Client::connect(shell.command(&serve_script(&agent, sudo)))
                .map_err(Failure::Start)
        }
        connected => connected.map_err(Failure::Start),
    }
}

/// Whether starting `agent` failed because it is not there.
fn vanished(error: &io::Error, agent: &str) -> bool {
    let message = error.to_string();
    let name = agent.rsplit('/').next().unwrap_or(agent);
    message.contains(name)
        && (message.contains("not found") || message.contains("No such file"))
}

/// Make sure the agent for the host's architecture is in
/// `~/.cache/disktree` there, and return its path relative to the home
/// directory. Copies it only when missing.
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "connect_installed calls install_with")
)]
pub fn install(
    shell: &Shell,
    agents: impl Fn(&str) -> Option<&'static [u8]>,
    mut stage: impl FnMut(Stage),
) -> Result<String, String> {
    install_with(shell, &agents, false, &mut stage)
}

/// [`install`], copying the agent even when the probe saw it when `again`.
fn install_with(
    shell: &Shell,
    agents: &impl Fn(&str) -> Option<&'static [u8]>,
    again: bool,
    stage: &mut impl FnMut(Stage),
) -> Result<String, String> {
    let probe = parse_probe(&shell.run(PROBE, &[])?)
        .ok_or("the probe there did not say what machine it is")?;
    let agent = agents(&probe.arch).ok_or_else(|| {
        format!(
            "this disktree carries no agent for {}: run `make agent`, then \
             build disktree again",
            probe.arch
        )
    })?;
    let name = agent_name(agent);
    if again || !probe.present.contains(&name) {
        stage(Stage::Installing);
        let said =
            shell.run_script(&install_script(&name, agent.len()), agent)?;
        finished(&said)?;
    }
    stage(Stage::Starting);
    Ok(format!("{AGENT_DIR}/{name}"))
}

/// What the install script says last, on a line of its own, once the
/// agent is in place.
const INSTALLED: &str = "disktree-agent-installed";

/// Whether the install script said [`INSTALLED`]. A script that never ran
/// exits 0 too: without `dd` there, the reader hands `eval` nothing.
fn finished(said: &str) -> Result<(), String> {
    if said.lines().any(|line| line.trim() == INSTALLED) {
        Ok(())
    } else {
        Err("the install script there did not run to its end; it needs \
             sh, dd, cat, wc, chmod, mv and find"
            .into())
    }
}

/// How long an agent nobody started stays. Each start touches the agent,
/// so this is the time since it was last used: two builds on two
/// machines that connect to one host keep each other's agents.
const STALE_DAYS: u32 = 7;

/// Read the agent from stdin into a temporary name, check its length,
/// make it executable and move it into place in one step, so a cut
/// connection never leaves a half agent under the real name. Then remove
/// the agents nobody started for [`STALE_DAYS`]: plain files named
/// `agent-*` in that folder, nothing else; and the partial uploads of
/// installs whose shell was killed before its `trap` ran, a day on, when
/// no install still writes them. A cleanup that fails costs nothing; the
/// agent is already in place. Ends with [`INSTALLED`].
fn install_script(name: &str, length: usize) -> String {
    // `-mtime +N` counts whole days past N.
    let stale = STALE_DAYS - 1;
    format!(
        "set -e
dir=\"$HOME/{AGENT_DIR}\"
mkdir -p \"$dir\"
part=\"$dir/.{name}.$$\"
trap 'rm -f \"$part\"' EXIT
cat > \"$part\"
size=$(wc -c < \"$part\")
if [ \"$size\" -ne {length} ]; then
  echo \"the agent arrived with $size of {length} bytes\" >&2
  exit 1
fi
chmod 755 \"$part\"
mv -f \"$part\" \"$dir/{name}\"
find \"$dir\" -maxdepth 1 -type f -name 'agent-*' ! -name '{name}' \\
  -mtime +{stale} -exec rm -f {{}} \\; 2>/dev/null || true
find \"$dir\" -maxdepth 1 -type f -name '.agent-*.*' -mtime +0 \\
  -exec rm -f {{}} \\; 2>/dev/null || true
echo {INSTALLED}
"
    )
}

/// The trash a host's agent offers, as the review screen may offer it.
///
/// None under `--sudo`, whatever the agent says: it runs as root with the
/// ssh user's `HOME`, so every entry would land in the user's trash owned
/// by root, and only root could empty it. The agent refuses that itself,
/// too; this keeps the choice off screen.
const fn trash_offered(reach: &Reach, hello: Option<&Hello>) -> TrashBackend {
    match (reach, hello) {
        (Reach::Ssh { sudo: true }, _) | (_, None) => TrashBackend::Unavailable,
        (_, Some(hello)) => hello.trash,
    }
}

/// Start the installed agent, under `sudo -n` when asked. Under sudo,
/// `HOME` stays the ssh user's: the removal guards protect the home
/// directory, and root's would leave the user's unguarded.
fn serve_script(agent: &str, sudo: bool) -> String {
    let agent = format!("\"$HOME/{agent}\"");
    // Touched first, without creating it: the cleanup goes by when an
    // agent was last started.
    let touch = format!("touch -c {agent} 2>/dev/null;");
    if sudo {
        format!("{touch} exec sudo -n env HOME=\"$HOME\" {agent} serve")
    } else {
        format!("{touch} exec {agent} serve")
    }
}

fn lock<T: ?Sized>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// A stand-in agent: what is installed is only ever copied, not run.
    static FAKE: &[u8] = b"#!/bin/sh\necho agent\n";

    fn fake(arch: &str) -> Option<&'static [u8]> {
        (arch == std::env::consts::ARCH).then_some(FAKE)
    }

    fn stages(shell: &Shell) -> (Result<String, String>, Vec<Stage>) {
        let mut seen = Vec::new();
        let outcome = install(shell, fake, |stage| seen.push(stage));
        (outcome, seen)
    }

    #[test]
    fn a_missing_agent_is_installed_and_stale_ones_are_removed() {
        let home = tempfile::tempdir().expect("home");
        let dir = home.path().join(AGENT_DIR);
        std::fs::create_dir_all(dir.join("agent-folder")).expect("folders");
        // One nobody started for ten days, and one another build started
        // today: only the first goes.
        let stale = dir.join("agent-0123456789abcdef");
        std::fs::write(&stale, "old").expect("old");
        std::fs::File::options()
            .write(true)
            .open(&stale)
            .and_then(|file| {
                file.set_modified(
                    std::time::SystemTime::now()
                        - Duration::from_hours(10 * 24),
                )
            })
            .expect("age it");
        std::fs::write(dir.join("agent-fedcba9876543210"), "in use")
            .expect("in use");
        // A partial upload whose shell was killed two days ago, and one
        // another install is writing now.
        let abandoned = dir.join(".agent-0123456789abcdef.4242");
        std::fs::write(&abandoned, "half").expect("abandoned");
        std::fs::File::options()
            .write(true)
            .open(&abandoned)
            .and_then(|file| {
                file.set_modified(
                    std::time::SystemTime::now() - Duration::from_hours(2 * 24),
                )
            })
            .expect("age it");
        let writing = dir.join(".agent-fedcba9876543210.4343");
        std::fs::write(&writing, "half").expect("writing");
        std::fs::write(dir.join("notes.txt"), "keep").expect("notes");
        std::os::unix::fs::symlink(
            home.path().join("elsewhere"),
            dir.join("agent-link"),
        )
        .expect("link");
        let shell = Shell::Local {
            home: home.path().to_path_buf(),
        };

        let (outcome, seen) = stages(&shell);
        let name = agent_name(FAKE);
        assert_eq!(outcome, Ok(format!("{AGENT_DIR}/{name}")));
        assert_eq!(seen, [Stage::Installing, Stage::Starting]);
        let installed = dir.join(&name);
        assert_eq!(std::fs::read(&installed).expect("installed"), FAKE);
        let mode = std::fs::metadata(&installed).expect("mode").permissions();
        assert_eq!(mode.mode() & 0o777, 0o755);
        assert!(!stale.exists(), "stale agent");
        assert!(
            dir.join("agent-fedcba9876543210").exists(),
            "another build's agent, started within the week"
        );
        assert!(dir.join("notes.txt").exists(), "not an agent");
        assert!(dir.join("agent-folder").is_dir(), "not a file");
        assert!(dir.join("agent-link").symlink_metadata().is_ok(), "a link");
        assert!(!abandoned.exists(), "an abandoned partial upload");
        assert!(writing.exists(), "another install's upload in flight");
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .expect("listing")
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with('.'))
                    && *path != writing
            })
            .collect();
        assert!(leftovers.is_empty(), "this upload was left: {leftovers:?}");
    }

    /// A host without `dd` reads no script, and its shell exits 0 having
    /// done nothing: the missing marker says the install did not run.
    #[test]
    fn an_install_that_never_ran_is_a_failure() {
        let home = tempfile::tempdir().expect("home");
        let shell = Shell::Local {
            home: home.path().to_path_buf(),
        };
        let said = shell
            .run(
                "eval \"$(no-such-dd bs=1 count=5 2>/dev/null)\"",
                b"echo hi",
            )
            .expect("the shell exits 0");
        let error = finished(&said).expect_err("not installed");
        assert!(error.contains("did not run to its end"), "{error}");

        let said = shell
            .run_script(&install_script(&agent_name(FAKE), FAKE.len()), FAKE)
            .expect("installed");
        assert_eq!(finished(&said), Ok(()));
    }

    #[test]
    fn a_present_agent_is_not_copied_again() {
        let home = tempfile::tempdir().expect("home");
        let shell = Shell::Local {
            home: home.path().to_path_buf(),
        };
        assert!(stages(&shell).0.is_ok());
        let installed = home.path().join(AGENT_DIR).join(agent_name(FAKE));
        // Changed in place: a second install would put the original back.
        std::fs::write(&installed, "touched").expect("touch");
        let (outcome, seen) = stages(&shell);
        assert!(outcome.is_ok());
        assert_eq!(seen, [Stage::Starting], "nothing installed");
        assert_eq!(std::fs::read(&installed).expect("read"), b"touched");
    }

    #[test]
    fn a_machine_this_build_has_no_agent_for_says_how_to_get_one() {
        let home = tempfile::tempdir().expect("home");
        let shell = Shell::Local {
            home: home.path().to_path_buf(),
        };
        let error =
            install(&shell, |_| None, |_| {}).expect_err("no agent at all");
        assert!(error.contains("carries no agent for"), "{error}");
        assert!(error.contains("make agent"), "{error}");
        assert!(!home.path().join(AGENT_DIR).exists(), "nothing written");
    }

    #[test]
    fn a_failing_shell_reports_what_it_said() {
        let home = tempfile::tempdir().expect("home");
        let shell = Shell::Local {
            home: home.path().to_path_buf(),
        };
        let error = shell
            .run("echo no route to host >&2; exit 255", &[])
            .expect_err("failed");
        assert_eq!(error, "no route to host");
    }

    #[test]
    fn the_probe_names_the_architecture_the_way_the_agents_are_built() {
        // A login shell that talks: its lines are passed over.
        let probe = parse_probe(
            "Welcome!\narch=arm64\nhave=agent-00\nhave=agent-*\nbye\n",
        )
        .expect("probe");
        assert_eq!(probe.arch, "aarch64");
        assert_eq!(probe.present, ["agent-00", "agent-*"]);
        assert_eq!(parse_probe("arch=amd64\n").expect("probe").arch, "x86_64");
        assert_eq!(parse_probe("x86_64\n"), None, "unmarked");
        assert_eq!(parse_probe(""), None);

        let home = tempfile::tempdir().expect("home");
        let shell = Shell::Local {
            home: home.path().to_path_buf(),
        };
        let probe = parse_probe(&shell.run(PROBE, &[]).expect("probe"))
            .expect("parsed");
        assert!(!probe.arch.is_empty());
        assert_eq!(probe.present, ["agent-*"], "an empty folder's glob");
    }

    /// A script of many lines, with quotes of both kinds, reaches `sh`
    /// whole, and its payload after it byte for byte.
    #[test]
    fn a_script_and_its_payload_arrive_apart() {
        let home = tempfile::tempdir().expect("home");
        let shell = Shell::Local {
            home: home.path().to_path_buf(),
        };
        let payload: Vec<u8> = (0..=255).cycle().take(300_000).collect();
        let script = "set -e\nsaid='it''s'\necho \"$said\"\n\
                      cat > \"$HOME/payload\"\nwc -c < \"$HOME/payload\"\n";
        let output = shell.run_script(script, &payload).expect("ran");
        assert_eq!(
            output.split_whitespace().collect::<Vec<_>>(),
            ["its", "300000"]
        );
        assert_eq!(
            std::fs::read(home.path().join("payload")).expect("payload"),
            payload
        );
    }

    /// The agent the probe saw is gone when it is started, as when
    /// another build's cleanup took it: it is installed again, once, and
    /// started.
    #[test]
    fn an_agent_that_vanished_is_installed_again_once() {
        let built = std::env::current_exe()
            .ok()
            .and_then(|exe| {
                Some(exe.parent()?.parent()?.join("disktree-agent"))
            })
            .filter(|agent| agent.is_file())
            .expect("build the agent first: cargo build -p disktree-agent");
        let real: &'static [u8] =
            Box::leak(std::fs::read(built).expect("agent").into_boxed_slice());
        let agents =
            |arch: &str| (arch == std::env::consts::ARCH).then_some(real);
        let home = tempfile::tempdir().expect("home");
        let dir = home.path().join(AGENT_DIR);
        std::fs::create_dir_all(&dir).expect("dir");
        std::os::unix::fs::symlink(
            home.path().join("gone"),
            dir.join(agent_name(real)),
        )
        .expect("a name with nothing behind it");
        let shell = Shell::Local {
            home: home.path().to_path_buf(),
        };
        let mut seen = Vec::new();
        let client =
            connect_installed(&shell, agents, false, |stage| seen.push(stage))
                .expect("connected after installing again");
        assert_eq!(seen, [Stage::Starting, Stage::Installing, Stage::Starting]);
        assert_eq!(client.hello().protocol, disktree_agent::PROTOCOL);
        let installed = dir.join(agent_name(real));
        assert!(installed.symlink_metadata().expect("there").is_file());
    }

    #[test]
    fn the_agent_runs_as_the_ssh_user_or_under_sudo_with_their_home() {
        let touch = "touch -c \"$HOME/.cache/disktree/agent-ab\" 2>/dev/null;";
        assert_eq!(
            serve_script(".cache/disktree/agent-ab", false),
            format!("{touch} exec \"$HOME/.cache/disktree/agent-ab\" serve")
        );
        assert_eq!(
            serve_script(".cache/disktree/agent-ab", true),
            format!(
                "{touch} exec sudo -n env HOME=\"$HOME\" \
                 \"$HOME/.cache/disktree/agent-ab\" serve"
            )
        );
        let error = io::Error::other("sudo: a password is required");
        assert!(explain("spark-1", true, &error).contains("never prompts"));
    }

    fn hello(home: Option<&str>, mounts: &[(&str, &str)]) -> Hello {
        let mut hello = disktree_agent::serve::hello();
        hello.home = home.map(PathBuf::from);
        hello.mounts = mounts
            .iter()
            .map(|(source, point)| disktree_core::space::Mount {
                source: (*source).into(),
                point: PathBuf::from(point),
                fstype: "ext4".into(),
                options: "rw".into(),
            })
            .collect();
        hello
    }

    #[test]
    fn the_first_root_is_the_sparkos_disk_or_the_home_directory() {
        let sparkos = hello(
            Some("/home/me"),
            &[("overlay", "/"), ("/dev/nvme0n1p2", SPARKOS_DISK)],
        );
        let plain = hello(
            Some("/home/me"),
            &[("/dev/sda2", "/"), ("/dev/sda3", "/home")],
        );
        assert_eq!(
            first_root(&Ask::Default, &sparkos),
            Some(PathBuf::from(SPARKOS_DISK))
        );
        assert_eq!(
            first_root(&Ask::Default, &plain),
            Some(PathBuf::from("/home/me"))
        );
        assert_eq!(
            first_root(&Ask::Disk, &plain),
            Some(PathBuf::from("/home"))
        );
        // `-D` on SparkOS: home is a bind of the real disk, which is what
        // the whole disk means there.
        let bound = hello(
            Some("/home/me"),
            &[
                ("overlay", "/"),
                ("/dev/nvme0n1p2", SPARKOS_DISK),
                ("/dev/nvme0n1p2", "/home"),
                ("/dev/nvme0n1p2", "/srv"),
            ],
        );
        assert_eq!(
            first_root(&Ask::Disk, &bound),
            Some(PathBuf::from(SPARKOS_DISK))
        );
        let elsewhere = hello(
            Some("/home/me"),
            &[
                ("overlay", "/"),
                ("/dev/nvme0n1p2", SPARKOS_DISK),
                ("/dev/sdb1", "/home"),
            ],
        );
        assert_eq!(
            first_root(&Ask::Disk, &elsewhere),
            Some(PathBuf::from("/home")),
            "a home on another disk keeps its own"
        );
        assert_eq!(
            first_root(&Ask::Path("models".into()), &plain),
            Some(PathBuf::from("/home/me/models"))
        );
        assert_eq!(
            first_root(&Ask::Path("/srv".into()), &plain),
            Some(PathBuf::from("/srv"))
        );
        assert_eq!(
            first_root(&Ask::Path("~".into()), &plain),
            Some(PathBuf::from("/home/me"))
        );
        assert_eq!(
            first_root(&Ask::Path("~/models".into()), &plain),
            Some(PathBuf::from("/home/me/models"))
        );
        assert_eq!(first_root(&Ask::Default, &hello(None, &[])), None);
    }

    /// A bare word that is no local path and no host it can resolve is
    /// said as both; `host:path` and a real failure keep ssh's words.
    #[test]
    fn a_bare_word_ssh_cannot_resolve_is_named_as_neither() {
        let mut remote = Remote::new(
            "projetcs".into(),
            Reach::Ssh { sudo: false },
            Ask::Default,
        );
        let unresolved = "ssh: Could not resolve hostname projetcs: Name or \
                          service not known";
        assert_eq!(remote.unreachable(unresolved), unresolved_as_typed());
        remote.bare = true;
        assert_eq!(
            remote.unreachable(unresolved),
            "no local path or ssh host named projetcs"
        );
        assert_eq!(
            remote.unreachable("Permission denied (publickey)."),
            "projetcs: Permission denied (publickey)."
        );
    }

    fn unresolved_as_typed() -> String {
        "projetcs: ssh: Could not resolve hostname projetcs: Name or service \
         not known"
            .into()
    }

    #[test]
    fn sudo_never_offers_the_trash() {
        let mut said = hello(Some("/home/me"), &[]);
        said.trash = TrashBackend::XdgHome;
        let offered = |sudo| trash_offered(&Reach::Ssh { sudo }, Some(&said));
        assert_eq!(offered(false), TrashBackend::XdgHome);
        assert_eq!(offered(true), TrashBackend::Unavailable);
        assert_eq!(
            trash_offered(&Reach::Ssh { sudo: false }, None),
            TrashBackend::Unavailable,
            "not connected"
        );
    }

    /// A remote played by a script: it introduces itself as an agent and
    /// then runs `then`.
    fn scripted(temp: &Path, then: &str) -> Remote {
        let mut introduction = disktree_agent::protocol::preamble();
        disktree_agent::wire::write_frame(
            &mut introduction,
            disktree_agent::protocol::tag::HELLO,
            &disktree_agent::serve::hello().encode(),
        )
        .expect("hello");
        std::fs::write(temp.join("hello"), introduction).expect("hello");
        let agent = temp.join("agent");
        std::fs::write(
            &agent,
            format!(
                "#!/bin/sh\ncat '{}'\n{then}\n",
                temp.join("hello").display()
            ),
        )
        .expect("agent");
        std::fs::set_permissions(
            &agent,
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("chmod");
        let remote =
            Remote::new("testhost".into(), Reach::Direct(agent), Ask::Default);
        remote.connect().expect("connected");
        remote
    }

    fn junk(path: &str) -> Target {
        Target {
            path: PathBuf::from(path),
            bytes: 10,
            is_dir: false,
            hidden: false,
        }
    }

    /// An agent that never answers holds up nothing the screens call:
    /// the plan says it is checking and free space is not known yet, at
    /// once, however long the agent takes.
    #[test]
    fn asks_never_wait_on_an_agent_that_does_not_answer() {
        let temp = tempfile::tempdir().expect("temp");
        let remote = scripted(temp.path(), "sleep 30");
        let started = Instant::now();
        let plan = remote.plan(&[junk("/srv/junk")], Path::new("/srv"));
        assert!(is_checking(&plan), "{plan:?}");
        assert!(plan.targets.is_empty(), "nothing acts unjudged");
        assert!(remote.report(Path::new("/srv")).is_none());
        let again = remote.plan(&[junk("/srv/junk")], Path::new("/srv"));
        assert!(is_checking(&again), "one ask per set of marks");
        assert!(started.elapsed() < Duration::from_millis(500), "it waited");
    }

    /// A plan the agent could not judge is not kept as its answer: it is
    /// said for a moment, then asked again.
    #[test]
    fn a_plan_that_failed_is_asked_again() {
        let temp = tempfile::tempdir().expect("temp");
        // The real agent: it refuses a relative root without judging.
        let agent = std::env::current_exe()
            .ok()
            .and_then(|exe| {
                Some(exe.parent()?.parent()?.join("disktree-agent"))
            })
            .filter(|agent| agent.is_file());
        let Some(agent) = agent else {
            panic!("build the agent first: cargo build -p disktree-agent");
        };
        let remote =
            Remote::new("testhost".into(), Reach::Direct(agent), Ask::Default);
        remote.connect().expect("connected");
        let targets = [junk("/srv/junk")];
        let root = Path::new("relative");
        let mut plan = remote.plan(&targets, root);
        let started = Instant::now();
        while is_checking(&plan) {
            assert!(started.elapsed() < Duration::from_secs(10), "no answer");
            std::thread::sleep(Duration::from_millis(5));
            plan = remote.plan(&targets, root);
        }
        assert!(
            plan.blocked[0].reason.contains("not an absolute path"),
            "{plan:?}"
        );
        assert!(remote.answers() > 0, "the window hears of it");
        std::thread::sleep(RETRY + Duration::from_millis(100));
        assert!(
            is_checking(&remote.plan(&targets, root)),
            "asked again, not kept"
        );
        let _ = temp;
    }

    #[test]
    fn a_plan_that_cannot_be_asked_removes_nothing() {
        let remote = Remote::new(
            "spark-1".into(),
            Reach::Ssh { sudo: false },
            Ask::Default,
        );
        let target = Target {
            path: PathBuf::from("/srv/junk"),
            bytes: 10,
            is_dir: false,
            hidden: false,
        };
        let plan = remote.plan(&[target], Path::new("/srv"));
        assert!(plan.targets.is_empty());
        assert_eq!(plan.blocked.len(), 1);
        assert!(plan.blocked[0].reason.contains("not connected to spark-1"));
    }
}
