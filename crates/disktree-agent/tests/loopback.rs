//! The built agent binary as a child process, driven through [`Client`]
//! exactly as the app drives one over ssh.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use disktree_agent::tree_codec::same_tree;
use disktree_agent::{Client, PROTOCOL};
use disktree_core::removal::{Plan, RemovalEvent, RemovalMode, Target, plan};
use disktree_core::scan::{ScanOptions, scan};
use tempfile::TempDir;

fn agent() -> Client {
    let mut command = Command::new(env!("CARGO_BIN_EXE_disktree-agent"));
    command.arg("serve");
    Client::connect(command).expect("the agent introduces itself")
}

fn write(path: &Path, bytes: usize) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, vec![b'x'; bytes]).unwrap();
}

/// Nesting, hidden entries, odd names, a hardlink pair and a symlink.
fn sample_tree() -> TempDir {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    write(&root.join("big/data.bin"), 300_000);
    write(&root.join("big/nested/deeper/leaf.bin"), 5_000);
    write(&root.join(".hidden/secret"), 9_000);
    write(&root.join("line\nbreak/name with spaces"), 100);
    write(&root.join("unicode/caf\u{e9} \u{1F600}"), 1);
    write(&root.join("node_modules/pkg/index.js"), 2_000);
    for index in 0..500 {
        write(&root.join(format!("many/f{index}")), index * 3);
    }
    // Both names in one directory, so every scan charges the same one.
    let linked = root.join("links/a/b/c/original");
    write(&linked, 64_000);
    fs::hard_link(&linked, root.join("links/a/b/c/second")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        std::os::unix::fs::symlink(&linked, root.join("a link")).unwrap();
        let raw = std::ffi::OsStr::from_bytes(b"latin1-\xe9");
        write(&root.join("bytes").join(raw), 10);
    }
    temp
}

fn nodes(tree: &disktree_core::tree::Node) -> u64 {
    1 + tree.children.iter().map(nodes).sum::<u64>()
}

#[test]
fn hello_describes_this_machine() {
    let client = agent();
    let hello = client.hello();
    assert_eq!(hello.protocol, PROTOCOL);
    assert_eq!(hello.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(hello.arch, std::env::consts::ARCH);
    assert_eq!(hello.os, std::env::consts::OS);
    assert_eq!(hello.home, std::env::home_dir());
    #[cfg(target_os = "linux")]
    assert!(!hello.mounts.is_empty(), "the agent reads the mount table");
}

#[test]
fn a_remote_scan_matches_a_local_scan_field_by_field() {
    let temp = sample_tree();
    let options = ScanOptions::default();
    let local = scan(temp.path(), options.clone()).unwrap();

    let client = agent();
    let remote = client.scan(temp.path(), &options);
    let tree = remote.wait().unwrap();
    same_tree(&local, &tree).unwrap();
    assert!(local.files > 500, "the sample is not trivially small");

    let progress = remote.progress();
    assert!(progress.finished);
    assert_eq!(progress.files, local.files + 1, "both links were listed");
    let transfer = remote.transfer().expect("the tree crossed the wire");
    assert_eq!(transfer.nodes, nodes(&local));
    assert!(
        transfer.wire_bytes < transfer.raw_bytes,
        "zstd earned its keep"
    );
}

#[test]
fn every_option_reaches_the_agent() {
    let temp = sample_tree();
    let options = ScanOptions {
        apparent_size: true,
        include_hidden: false,
        max_depth: Some(2),
        dedup_hardlinks: false,
        metric: disktree_core::tree::Metric::Files,
        ..ScanOptions::default()
    };
    let local = scan(temp.path(), options.clone()).unwrap();
    let tree = agent().scan(temp.path(), &options).wait().unwrap();
    same_tree(&local, &tree).unwrap();
}

#[test]
fn a_scan_that_cannot_start_fails_with_its_reason() {
    let missing = std::env::temp_dir().join("disktree-agent-no-such-dir");
    let error = agent()
        .scan(&missing, &ScanOptions::default())
        .wait()
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound, "{error}");
}

/// A whole volume takes long enough to cancel partway through.
#[test]
fn a_scan_cancelled_midway_stops_and_the_agent_keeps_serving() {
    let root = if cfg!(windows) {
        PathBuf::from("C:\\")
    } else {
        "/".into()
    };
    let client = agent();
    let remote = client.scan(&root, &ScanOptions::default());
    let deadline = Instant::now() + Duration::from_secs(30);
    while remote.progress().files == 0 {
        assert!(Instant::now() < deadline, "no progress from the agent");
        assert!(remote.poll().is_none(), "finished before it was cancelled");
        std::thread::sleep(Duration::from_millis(20));
    }
    remote.cancel();
    let started = Instant::now();
    let error = remote.wait().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::Interrupted, "{error}");
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(remote.progress().cancelled);
    // The connection outlives the cancelled scan.
    assert!(client.space(&root).unwrap().space.is_ok());
}

#[test]
fn space_and_volumes_are_read_on_the_agent() {
    let temp = TempDir::new().unwrap();
    let client = agent();
    let report = client.space(temp.path()).unwrap();
    let local = disktree_core::space::space_info(temp.path()).unwrap();
    let remote = report.space.unwrap();
    assert_eq!(remote.total, local.total);
    assert_eq!(
        report.volume_root,
        disktree_core::space::volume_root_for(temp.path())
    );
    assert_eq!(report.device, disktree_core::space::device_for(temp.path()));
    let volumes = client.volumes().unwrap();
    let points = |volumes: &[disktree_core::space::Volume]| {
        volumes.iter().map(|v| v.point.clone()).collect::<Vec<_>>()
    };
    assert_eq!(points(&volumes), points(&disktree_core::space::volumes()));
}

#[test]
fn git_state_and_path_info_are_read_on_the_agent() {
    let temp = TempDir::new().unwrap();
    let client = agent();
    let root = temp.path();
    write(&root.join("dir/file"), 10);
    assert_eq!(client.git_state(&root.join("dir")).unwrap(), None);
    let initialised = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["init", "-q"])
        .status()
        .is_ok_and(|status| status.success());
    if initialised {
        let state = client.git_state(root).unwrap().expect("a checkout");
        assert_eq!(state, disktree_core::git::state(root).unwrap());
        assert_eq!(state.changed, Some(1), "dir/ is untracked");
    }

    let info = client.path_info(&root.join("dir/../dir")).unwrap();
    assert_eq!(
        info.canonical,
        Some(fs::canonicalize(root.join("dir")).unwrap())
    );
    assert_eq!(info.is_dir, Ok(true));
    assert!(info.exists);
    let file = client.path_info(&root.join("dir/file")).unwrap();
    assert_eq!(file.is_dir, Ok(false));
    let missing = client.path_info(&root.join("gone")).unwrap();
    assert!(!missing.exists);
    assert_eq!(missing.canonical, None);
    assert!(missing.is_dir.is_err());
}

fn target(path: &Path, bytes: u64) -> Target {
    Target {
        path: path.to_path_buf(),
        bytes,
        is_dir: path.is_dir(),
        hidden: false,
    }
}

#[cfg(unix)]
fn link_dir(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

#[cfg(windows)]
fn link_dir(target: &Path, link: &Path) {
    std::os::windows::fs::symlink_dir(target, link).unwrap();
}

/// What `removal::plan` refuses locally: the scanned root, paths outside
/// it, the home directory, a path reached through a link.
fn guard_cases(root: &Path, keep: &Path) -> Vec<Target> {
    link_dir(keep, &root.join("link"));
    let mut targets = vec![
        target(root, 0),
        target(&keep.join("precious.bin"), 4),
        target(&root.join("link/precious.bin"), 4),
        target(Path::new("/"), 0),
    ];
    if let Some(home) = std::env::home_dir() {
        targets.push(target(&home, 0));
    }
    targets
}

#[test]
fn the_agent_plans_what_removal_plan_plans() {
    let temp = sample_tree();
    let keep = TempDir::new().unwrap();
    write(&keep.path().join("precious.bin"), 4);
    let mut targets = guard_cases(temp.path(), keep.path());
    targets.push(target(&temp.path().join("big"), 305_000));
    targets.push(target(&temp.path().join("big/data.bin"), 300_000));

    let local = plan(&targets, temp.path());
    let remote = agent().plan(&targets, temp.path()).unwrap();
    assert_eq!(remote.targets, local.targets);
    assert_eq!(remote.covered, local.covered);
    assert_eq!(remote.blocked, local.blocked);
    assert_eq!(remote.root, local.root);
    assert_eq!(remote.reclaim(), local.reclaim());
    assert_eq!(remote.foreign(), local.foreign());
    assert_eq!(local.blocked.len(), targets.len() - 2, "only big is kept");
}

/// A client that claims everything is safe: the agent re-plans and
/// removes only what its own plan allows.
#[test]
fn a_forged_plan_removes_only_what_the_agent_allows() {
    let temp = sample_tree();
    let root = temp.path();
    let keep = TempDir::new().unwrap();
    write(&keep.path().join("precious.bin"), 4);
    let mut targets = guard_cases(root, keep.path());
    // The home directory is never sent, even forged: this test must not
    // depend on the guard it checks to keep a real home safe.
    targets
        .retain(|target| Some(&target.path) != std::env::home_dir().as_ref());
    let marked = root.join("big");
    targets.push(target(&marked, 305_000));
    let refused = targets.len() - 1;
    let forged = Plan::from_parts(
        targets,
        Vec::new(),
        Vec::new(),
        root.to_path_buf(),
        0,
        0,
    );

    let client = agent();
    let run = client.remove(&forged, RemovalMode::Permanent);
    let mut items = Vec::new();
    let done = loop {
        match run.next().expect("the removal reaches its end") {
            RemovalEvent::Start { total } => assert_eq!(total, refused + 1),
            RemovalEvent::Item { path, outcome, .. } => {
                items.push((path, outcome));
            }
            done @ RemovalEvent::Done { .. } => break done,
            lost @ RemovalEvent::Lost { .. } => panic!("{lost:?}"),
        }
    };
    assert!(matches!(
        done,
        RemovalEvent::Done {
            removed: 1,
            bytes: 305_000,
            failed,
        } if failed == refused
    ));
    assert_eq!(items.len(), refused + 1);
    for (path, outcome) in &items {
        if path == &marked {
            assert!(outcome.is_ok(), "{outcome:?}");
        } else {
            let error = outcome.as_ref().unwrap_err();
            assert!(error.starts_with("refused: "), "{path:?}: {error}");
        }
    }

    assert!(!marked.exists(), "the marked directory is gone");
    assert!(keep.path().join("precious.bin").exists());
    assert!(root.join("many/f1").exists(), "unmarked neighbours stay");
    assert!(root.join(".hidden/secret").exists());

    // A root that is not one: empty and `.` would normalize to a prefix of
    // every path, and a relative one is read from the agent's directory.
    // Nothing is judged and nothing removed, in either mode.
    let outside = keep.path().join("precious.bin");
    let inside = root.join("many/f2");
    let forgeries = [
        (PathBuf::new(), outside.clone()),
        (PathBuf::from("."), outside.clone()),
        (PathBuf::from("relative/root"), outside.clone()),
        (root.join("big/.."), outside.clone()),
        (root.to_path_buf(), PathBuf::from("many/f2")),
        (root.to_path_buf(), root.join("big/../many/f2")),
    ];
    for (forged_root, path) in forgeries {
        let refused = client.plan(&[target(&path, 4)], &forged_root);
        let error = refused.expect_err("a forged root is not planned");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{error}");
        for mode in [RemovalMode::Permanent, RemovalMode::Trash] {
            let forged = Plan::from_parts(
                vec![target(&path, 4)],
                Vec::new(),
                Vec::new(),
                forged_root.clone(),
                0,
                0,
            );
            let run = client.remove(&forged, mode);
            let mut said = Vec::new();
            loop {
                match run.next().expect("the removal reaches its end") {
                    RemovalEvent::Done { removed, .. } => {
                        assert_eq!(removed, 0, "{forged_root:?} {path:?}");
                        break;
                    }
                    RemovalEvent::Item { outcome, .. } => said.push(outcome),
                    other @ (RemovalEvent::Start { .. }
                    | RemovalEvent::Lost { .. }) => panic!("{other:?}"),
                }
            }
            assert!(
                said.iter().any(|outcome| outcome
                    .as_ref()
                    .is_err_and(|error| error.contains("not an absolute"))),
                "{said:?}"
            );
        }
    }
    assert!(outside.exists(), "outside the root, under a forged one");
    assert!(inside.exists(), "a relative target");
}

#[cfg(unix)]
fn fake_agent(script: &str) -> std::io::Result<Client> {
    let mut command = Command::new("sh");
    command.args(["-c", script]);
    Client::connect(command)
}

#[cfg(unix)]
#[test]
fn another_protocol_is_a_clear_error_not_a_hang() {
    let started = Instant::now();
    let error = fake_agent("printf 'DTAG\\143'; sleep 30").unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(5), "it waited");
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    let message = error.to_string();
    assert!(message.contains("protocol 99"), "{message}");
    assert!(
        message.contains(&format!("protocol {PROTOCOL}")),
        "{message}"
    );
}

/// An agent from other sources than this client, as one left in
/// target/agent from before a fix: refused even at the same protocol.
#[cfg(unix)]
#[test]
fn an_agent_built_from_other_sources_is_refused() {
    let temp = TempDir::new().unwrap();
    let mut hello = disktree_agent::serve::hello();
    hello.build = "0123456789abcdef".into();
    let mut introduction = disktree_agent::protocol::preamble();
    disktree_agent::wire::write_frame(
        &mut introduction,
        disktree_agent::protocol::tag::HELLO,
        &hello.encode(),
    )
    .unwrap();
    let script = temp.path().join("introduction");
    fs::write(&script, introduction).unwrap();
    let error = fake_agent(&format!("cat '{}'; sleep 30", script.display()))
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    let message = error.to_string();
    assert!(message.contains("0123456789abcdef"), "{message}");
    assert!(
        message.contains(
            "this disktree carries a stale agent; run make agent and rebuild"
        ),
        "{message}"
    );
    assert_eq!(
        agent().hello().build,
        disktree_agent::protocol::BUILD,
        "the agent built beside this test is current"
    );
}

#[cfg(unix)]
#[test]
fn a_shell_banner_is_not_an_agent() {
    let error = fake_agent("echo 'Welcome to Ubuntu'; sleep 30").unwrap_err();
    assert!(
        error.to_string().contains("not a disktree agent"),
        "{error}"
    );
}

#[cfg(unix)]
#[test]
fn an_agent_that_is_missing_reports_what_the_shell_said() {
    let error =
        fake_agent("echo 'sh: disktree-agent: not found' >&2; exit 127")
            .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("exited before introducing"), "{message}");
    assert!(message.contains("disktree-agent: not found"), "{message}");
}

/// An agent whose link drops mid-removal: the removal ends as lost, with
/// no `Done` and so no counts, since the agent may have gone on.
#[cfg(unix)]
#[test]
fn a_removal_whose_link_drops_ends_lost_not_done() {
    use disktree_agent::protocol::{Reply, tag};
    use disktree_agent::wire::write_frame;

    let temp = TempDir::new().unwrap();
    let mut introduction = disktree_agent::protocol::preamble();
    write_frame(
        &mut introduction,
        tag::HELLO,
        &disktree_agent::serve::hello().encode(),
    )
    .unwrap();
    let mut events = Vec::new();
    for event in [
        RemovalEvent::Start { total: 3 },
        RemovalEvent::Item {
            path: temp.path().join("first"),
            bytes: 10,
            outcome: Ok(()),
        },
    ] {
        let (tag, payload) = Reply::Removal(event).encode(1);
        write_frame(&mut events, tag, &payload).unwrap();
    }
    fs::write(temp.path().join("introduction"), introduction).unwrap();
    fs::write(temp.path().join("events"), events).unwrap();
    // Introduce, wait for the request, say two events, and drop.
    let client = fake_agent(&format!(
        "cd '{}' && cat introduction && dd bs=1 count=1 2>/dev/null \
         >/dev/null && cat events && echo 'link dropped' >&2",
        temp.path().display()
    ))
    .unwrap();
    let plan = Plan::from_parts(
        vec![target(&temp.path().join("first"), 10)],
        Vec::new(),
        Vec::new(),
        temp.path().to_path_buf(),
        0,
        0,
    );
    let run = client.remove(&plan, RemovalMode::Permanent);
    let mut seen = Vec::new();
    while let Some(event) = run.next() {
        seen.push(event);
    }
    assert!(
        matches!(seen.as_slice(), [
            RemovalEvent::Start { total: 3 },
            RemovalEvent::Item { .. },
            RemovalEvent::Lost { reason },
        ] if reason.contains("link dropped")),
        "{seen:?}"
    );
}

/// An agent that introduces itself and then exits.
#[cfg(unix)]
#[test]
fn requests_after_the_agent_dies_fail_instead_of_waiting() {
    let temp = TempDir::new().unwrap();
    let mut introduction = disktree_agent::protocol::preamble();
    disktree_agent::wire::write_frame(
        &mut introduction,
        disktree_agent::protocol::tag::HELLO,
        &disktree_agent::serve::hello().encode(),
    )
    .unwrap();
    let script = temp.path().join("introduction");
    fs::write(&script, introduction).unwrap();
    let client = fake_agent(&format!(
        "cat '{}'; echo 'agent crashed' >&2",
        script.display()
    ))
    .unwrap();

    let started = Instant::now();
    let error = client.space(temp.path()).unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(5), "it waited");
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe, "{error}");
    let remote = client.scan(temp.path(), &ScanOptions::default());
    let message = remote.wait().unwrap_err().to_string();
    assert!(message.contains("agent crashed"), "{message}");
}
