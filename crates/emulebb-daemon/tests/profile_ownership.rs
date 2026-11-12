//! Non-protocol lifecycle regressions using real, isolated OS processes.

use std::{
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use emulebb_daemon::DaemonProfile;

const DEADLINE: Duration = Duration::from_secs(15);
const CHILD_PROFILE: &str = "PROFILE_OWNERSHIP_TEST_PROFILE";
const CHILD_MODE: &str = "PROFILE_OWNERSHIP_TEST_MODE";
const CHILD_READY: &str = "PROFILE_OWNERSHIP_TEST_READY";

struct OwnedChild(Child);

impl OwnedChild {
    fn start(profile: &Path, mode: &str, ready: &Path) -> Self {
        Self::start_command(
            Command::new(env::current_exe().unwrap()),
            profile,
            mode,
            ready,
        )
    }

    fn start_command(mut command: Command, profile: &Path, mode: &str, ready: &Path) -> Self {
        Self(
            command
                .args([
                    "--ignored",
                    "--exact",
                    "profile_ownership_child",
                    "--nocapture",
                ])
                .env(CHILD_PROFILE, profile)
                .env(CHILD_MODE, mode)
                .env(CHILD_READY, ready)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        )
    }

    fn finish(&mut self) {
        if let Some(mut input) = self.0.stdin.take() {
            let _ = input.write_all(b"stop\n");
        }
        let deadline = Instant::now() + DEADLINE;
        let status = loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "profile fixture did not exit");
            thread::sleep(Duration::from_millis(10));
        };
        let mut stderr = String::new();
        if let Some(mut pipe) = self.0.stderr.take() {
            pipe.read_to_string(&mut stderr).unwrap();
        }
        assert!(status.success(), "profile fixture failed: {stderr}");
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn temporary() -> tempfile::TempDir {
    let target = PathBuf::from(
        env::var_os("CARGO_TARGET_DIR").expect("profile ownership tests require CARGO_TARGET_DIR"),
    );
    assert!(target.is_absolute(), "CARGO_TARGET_DIR must be absolute");
    let root = target.join("tmp/profile-ownership-tests");
    fs::create_dir_all(&root).unwrap();
    tempfile::Builder::new()
        .prefix("lease-")
        .tempdir_in(root)
        .unwrap()
}

fn ready(path: &Path) -> String {
    let deadline = Instant::now() + DEADLINE;
    loop {
        if let Ok(value) = fs::read_to_string(path)
            && matches!(value.as_str(), "owned" | "busy")
        {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "profile fixture did not become ready"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn probe(profile: &Path, mode: &str, ready: &Path) {
    let mut child = OwnedChild::start(profile, mode, ready);
    child.finish();
}

fn profile_snapshot(profile: &Path) -> [Option<Vec<u8>>; 4] {
    [
        "emulebb-rust-settings.toml",
        "emulebb-rust-metadata.db",
        "emulebb-rust-metadata.db-wal",
        "emulebb-rust-metadata.db-shm",
    ]
    .map(|name| match fs::read(profile.join(name)) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("failed to snapshot synthetic profile {name}: {error}"),
    })
}

#[test]
fn metadata_handles_retain_ownership_after_profile_drop_and_process_death_releases_it() {
    let temporary = temporary();
    let profile = temporary.path().join("profile");
    let signal = temporary.path().join("ready");
    let mut holder = OwnedChild::start(&profile, "holder", &signal);
    assert_eq!(ready(&signal), "owned");
    // The holder is idle after READY. A denied process must not mutate even
    // uncheckpointed WAL state or the shared-memory sidecar, not just the DB.
    let before = profile_snapshot(&profile);
    probe(&profile, "busy", &temporary.path().join("probe"));
    assert!(
        before == profile_snapshot(&profile),
        "denied profile open changed bootstrap, database, WAL or SHM state"
    );
    holder.0.kill().unwrap();
    holder.0.wait().unwrap();
    assert!(profile.join(".emulebb-profile.lock").is_file());
    probe(&profile, "available", &temporary.path().join("after-death"));
}

#[test]
fn aliases_share_ownership_and_clean_exit_releases_it() {
    let temporary = temporary();
    let profile = temporary.path().join("profile");
    let signal = temporary.path().join("ready");
    let mut holder = OwnedChild::start(&profile, "holder", &signal);
    assert_eq!(ready(&signal), "owned");
    probe(&profile.join("."), "busy", &temporary.path().join("dot"));
    #[cfg(unix)]
    {
        let alias = temporary.path().join("alias");
        std::os::unix::fs::symlink(&profile, &alias).unwrap();
        probe(&alias, "busy", &temporary.path().join("symlink"));
    }
    #[cfg(windows)]
    {
        let alias = PathBuf::from(profile.to_string_lossy().to_uppercase());
        assert!(
            alias.is_dir(),
            "Windows case-alias fixture requires a case-insensitive volume"
        );
        probe(&alias, "busy", &temporary.path().join("case"));

        // Junctions do not require the symlink privilege. Keep both command
        // arguments fixed and relative to this test's unique scratch directory.
        let windows = PathBuf::from(env::var_os("SystemRoot").expect("Windows system root"));
        // WHY: cmd.exe rejects a mixed-separator executable path after launch.
        // Join native components to keep the fixture command valid.
        let creation = Command::new(windows.join("System32").join("cmd.exe"))
            .current_dir(temporary.path())
            .args(["/d", "/v:off", "/c", "mklink", "/J", "junction", "profile"])
            .output()
            .expect("create synthetic profile junction");
        assert!(
            creation.status.success(),
            "could not create synthetic profile junction: {}",
            String::from_utf8_lossy(&creation.stderr)
        );
        let junction = temporary.path().join("junction");
        assert_eq!(
            fs::canonicalize(&junction).unwrap(),
            fs::canonicalize(&profile).unwrap()
        );
        let before = profile_snapshot(&profile);
        probe(&junction, "busy", &temporary.path().join("junction-busy"));
        assert!(
            before == profile_snapshot(&profile),
            "denied junction open changed the owned profile"
        );
    }
    holder.finish();
    probe(&profile, "available", &temporary.path().join("after-exit"));
    #[cfg(windows)]
    {
        let junction = temporary.path().join("junction");
        probe(
            &junction,
            "available",
            &temporary.path().join("junction-after-exit"),
        );
        fs::remove_dir(&junction).unwrap();
        assert!(profile.is_dir(), "junction cleanup removed its target");
    }
}

#[test]
fn fresh_profile_creation_race_has_exactly_one_owner() {
    let temporary = temporary();
    let profile = temporary.path().join("fresh");
    let first_ready = temporary.path().join("first");
    let second_ready = temporary.path().join("second");
    let mut first = OwnedChild::start(&profile, "race", &first_ready);
    let mut second = OwnedChild::start(&profile, "race", &second_ready);
    let mut outcomes = [ready(&first_ready), ready(&second_ready)];
    outcomes.sort();
    assert_eq!(outcomes, ["busy", "owned"]);
    first.finish();
    second.finish();
    probe(&profile, "available", &temporary.path().join("after-race"));
}

#[test]
fn unrelated_profiles_can_be_owned_concurrently() {
    let temporary = temporary();
    let first_ready = temporary.path().join("first-ready");
    let second_ready = temporary.path().join("second-ready");
    let mut first = OwnedChild::start(&temporary.path().join("first"), "holder", &first_ready);
    let mut second = OwnedChild::start(&temporary.path().join("second"), "holder", &second_ready);
    assert_eq!(ready(&first_ready), "owned");
    assert_eq!(ready(&second_ready), "owned");
    first.finish();
    second.finish();
}

#[test]
#[ignore = "isolated subprocess fixture invoked by the ownership regression tests"]
fn profile_ownership_child() {
    let profile_path = PathBuf::from(env::var_os(CHILD_PROFILE).unwrap());
    let mode = env::var(CHILD_MODE).unwrap();
    let result = match mode.as_str() {
        "executable-default" => DaemonProfile::load(None),
        "explicit-dot" => DaemonProfile::load(Some(PathBuf::from("."))),
        "explicit-relative" => DaemonProfile::load(Some(PathBuf::from("selected-profile"))),
        "explicit-file" => DaemonProfile::load(Some(PathBuf::from("not-a-directory"))),
        _ => DaemonProfile::load_for_import(profile_path.clone()),
    };
    if mode == "explicit-file" {
        assert!(
            result.is_err(),
            "invalid selected profile must fail without fallback"
        );
        return;
    }
    if matches!(
        mode.as_str(),
        "executable-default" | "explicit-dot" | "explicit-relative"
    ) {
        let profile = result.unwrap();
        assert_eq!(
            fs::canonicalize(profile.profile_io_dir()).unwrap(),
            fs::canonicalize(&profile_path).unwrap()
        );
        assert!(profile_path.join("emulebb-rust-settings.toml").is_file());
        assert!(profile_path.join("emulebb-rust-metadata.db").is_file());
        assert_eq!(
            profile.rest.api_key,
            "change_me_123change_me_123change_me_123"
        );
        return;
    }
    if mode == "busy" {
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("profile is already in use")
        );
        return;
    }
    if mode == "race"
        && let Err(error) = &result
    {
        assert!(error.to_string().contains("profile is already in use"));
        fs::write(PathBuf::from(env::var_os(CHILD_READY).unwrap()), "busy").unwrap();
        return;
    }
    let profile = result.unwrap();
    if mode == "available" {
        return;
    }
    let first = profile.open_metadata_store().unwrap();
    let cloned = first.clone();
    let independent = profile.open_metadata_store().unwrap();
    drop(profile);
    drop(first);
    // The original profile is gone: only separate/cloned metadata handles keep
    // ownership alive while this process waits, rather than an early loader.
    fs::write(PathBuf::from(env::var_os(CHILD_READY).unwrap()), "owned").unwrap();
    let mut stop = String::new();
    std::io::stdin().read_line(&mut stop).unwrap();
    drop((cloned, independent));
}

#[test]
fn executable_default_ignores_shell_cwd_and_explicit_profiles_resolve_from_it() {
    let temporary = temporary();
    let executable_dir = temporary.path().join("portable-bin");
    let other_cwd = temporary.path().join("other-cwd");
    let unused_home = temporary.path().join("unused-home");
    for directory in [&executable_dir, &other_cwd, &unused_home] {
        fs::create_dir(directory).unwrap();
    }
    // WHY: invoking the original unit-test executable with no profile would
    // write beside a shared Cargo artifact. Copy the fixture into owned output.
    let current = env::current_exe().unwrap();
    let copied = executable_dir.join(current.file_name().unwrap());
    fs::copy(current, &copied).unwrap();
    fs::write(other_cwd.join("not-a-directory"), b"synthetic blocked path").unwrap();

    for (mode, cwd, expected) in [
        (
            "executable-default",
            other_cwd.as_path(),
            executable_dir.clone(),
        ),
        (
            "explicit-dot",
            executable_dir.as_path(),
            executable_dir.clone(),
        ),
        (
            "explicit-relative",
            other_cwd.as_path(),
            other_cwd.join("selected-profile"),
        ),
        (
            "explicit-file",
            other_cwd.as_path(),
            other_cwd.join("not-a-directory"),
        ),
    ] {
        let mut command = Command::new(&copied);
        command
            .current_dir(cwd)
            .env("HOME", &unused_home)
            .env("LOCALAPPDATA", &unused_home)
            .env("XDG_CONFIG_HOME", &unused_home);
        let mut child =
            OwnedChild::start_command(command, &expected, mode, &temporary.path().join("ready"));
        child.finish();
    }
    assert!(!other_cwd.join("emulebb-rust-settings.toml").exists());
    assert!(fs::read_dir(unused_home).unwrap().next().is_none());
}
