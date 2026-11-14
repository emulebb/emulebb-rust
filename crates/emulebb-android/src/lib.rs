//! Narrow application-host boundary; the Android shell owns no client settings.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    thread::JoinHandle,
};

use anyhow::{Context, Result, ensure};
use emulebb_daemon::{DaemonProfile, RestBootstrapSettings, ShutdownRequest, host_bootstrap};
use jni::{
    Env, native_method,
    objects::{JObject, JString},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

mod startup_network;
use startup_network::StartupNetwork;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", deny_unknown_fields)]
enum Request {
    ShareDiagnostics {
        profile_dir: PathBuf,
    },
    ValidateLink {
        link: String,
    },
    ReadSettings {
        profile_dir: PathBuf,
    },
    WriteSettings {
        profile_dir: PathBuf,
        bind_addr: String,
        api_key: String,
        web_root_dir: PathBuf,
    },
    PruneAssets {
        profile_dir: PathBuf,
        current_web_root: PathBuf,
    },
    Start {
        profile_dir: PathBuf,
        transfer_root: PathBuf,
        incoming_dir: PathBuf,
        shared_dir: PathBuf,
    },
    Stop {},
    NetworkChanged {},
    Status {},
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
enum Phase {
    #[default]
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
}

#[derive(Default)]
struct Host {
    phase: Phase,
    error: Option<String>,
    address: Option<String>,
    shutdown: Option<ShutdownRequest>,
    worker: Option<JoinHandle<()>>,
    startup_network: Option<Arc<StartupNetwork>>,
    waiting_for_network: bool,
}

fn host() -> &'static Mutex<Host> {
    static HOST: OnceLock<Mutex<Host>> = OnceLock::new();
    HOST.get_or_init(Mutex::default)
}

struct ProcessLogging {
    profile: PathBuf,
    _guard: emulebb_daemon::logging::LoggingGuard,
}

fn ensure_process_logging(profile: &std::path::Path) -> Result<()> {
    static LOGGING: OnceLock<Mutex<Option<ProcessLogging>>> = OnceLock::new();
    let mut logging = LOGGING
        .get_or_init(Mutex::default)
        .lock()
        .map_err(|_| anyhow::anyhow!("process logging state unavailable"))?;
    let profile = profile.canonicalize()?;
    if let Some(existing) = logging.as_ref() {
        ensure!(
            existing.profile == profile,
            "one Android service process owns one logging profile"
        );
    } else {
        *logging = Some(ProcessLogging {
            _guard: emulebb_daemon::logging::init_process(&profile)?,
            profile,
        });
    }
    Ok(())
}

fn handle(request: Request) -> Result<Value> {
    match request {
        Request::ShareDiagnostics { profile_dir } => {
            emulebb_daemon::support_diagnostics::capture(&profile_dir)
        }
        Request::ValidateLink { link } => {
            emulebb_daemon::validate_ed2k_file_link(&link)?;
            Ok(Value::String(link))
        }
        Request::PruneAssets {
            profile_dir,
            current_web_root,
        } => {
            host_bootstrap::while_stopped(&profile_dir, || {
                prune_assets(&profile_dir, &current_web_root)
            })?;
            Ok(Value::Null)
        }
        Request::ReadSettings { profile_dir } => {
            ensure!(
                profile_dir.is_absolute(),
                "profile directory must be absolute"
            );
            Ok(json!(host_bootstrap::read(&profile_dir)?))
        }
        Request::WriteSettings {
            profile_dir,
            bind_addr,
            api_key,
            web_root_dir,
        } => {
            ensure!(
                profile_dir.is_absolute() && web_root_dir.is_absolute(),
                "host directories must be absolute"
            );
            let rest = RestBootstrapSettings {
                bind_addr: Some(bind_addr.parse().context("invalid REST bind address")?),
                api_key,
                web_root_dir: Some(web_root_dir),
            };
            host_bootstrap::write(&profile_dir, rest)?;
            Ok(Value::Null)
        }
        Request::Start {
            profile_dir,
            transfer_root,
            incoming_dir,
            shared_dir,
        } => {
            ensure!(
                profile_dir.is_absolute()
                    && transfer_root.is_absolute()
                    && incoming_dir.is_absolute()
                    && shared_dir.is_absolute(),
                "host directories must be absolute"
            );
            let mut state = host()
                .lock()
                .map_err(|_| anyhow::anyhow!("host state unavailable"))?;
            if matches!(
                state.phase,
                Phase::Starting | Phase::Running | Phase::Stopping
            ) {
                return Ok(Value::Null);
            }
            if let Some(worker) = &state.worker {
                ensure!(worker.is_finished(), "previous runtime is still draining");
            }
            if let Some(worker) = state.worker.take() {
                let _ = worker.join();
            }
            let shutdown = ShutdownRequest::default();
            state.phase = Phase::Starting;
            state.error = None;
            state.address = None;
            state.shutdown = Some(shutdown.clone());
            let startup_network = Arc::new(StartupNetwork::default());
            state.startup_network = Some(Arc::clone(&startup_network));
            state.waiting_for_network = false;
            let worker = std::thread::Builder::new()
                .name("emulebb-android".into())
                .spawn(move || {
                    let outcome = std::panic::catch_unwind(|| {
                        run_worker(
                            profile_dir,
                            transfer_root,
                            incoming_dir,
                            shared_dir,
                            shutdown,
                            startup_network,
                        )
                    });
                    if let Ok(mut state) = host().lock() {
                        match outcome {
                            Ok(Ok(())) => {
                                state.phase = Phase::Stopped;
                                state.error = None;
                            }
                            Ok(Err(error)) => {
                                state.phase = Phase::Failed;
                                state.error = Some(format!("{error:#}"));
                            }
                            Err(_) => {
                                state.phase = Phase::Failed;
                                state.error = Some("native runtime failed".into());
                            }
                        }
                        state.shutdown = None;
                        state.startup_network = None;
                        state.waiting_for_network = false;
                        state.address = None;
                    }
                });
            match worker {
                Ok(worker) => state.worker = Some(worker),
                Err(error) => {
                    state.phase = Phase::Failed;
                    state.shutdown = None;
                    state.startup_network = None;
                    return Err(error.into());
                }
            }
            Ok(Value::Null)
        }
        Request::Stop {} => {
            let mut state = host()
                .lock()
                .map_err(|_| anyhow::anyhow!("host state unavailable"))?;
            if let Some(shutdown) = &state.shutdown {
                shutdown.request();
                state.phase = Phase::Stopping;
            }
            if let Some(network) = &state.startup_network {
                network.cancel()?;
            }
            Ok(Value::Null)
        }
        Request::NetworkChanged {} => {
            let state = host()
                .lock()
                .map_err(|_| anyhow::anyhow!("host state unavailable"))?;
            if let Some(network) = &state.startup_network {
                network.changed()?;
            }
            Ok(Value::Null)
        }
        Request::Status {} => {
            let state = host()
                .lock()
                .map_err(|_| anyhow::anyhow!("host state unavailable"))?;
            Ok(
                json!({"phase":state.phase,"error":state.error,"address":state.address,
                "waitingForNetwork":state.waiting_for_network}),
            )
        }
    }
}

fn run_worker(
    profile_dir: PathBuf,
    transfer_root: PathBuf,
    incoming_dir: PathBuf,
    shared_dir: PathBuf,
    shutdown: ShutdownRequest,
    network: Arc<StartupNetwork>,
) -> Result<()> {
    network.run(
        |ready| {
            if shutdown.subscribe().is_requested() {
                return Ok(());
            }
            run_attempt(
                &profile_dir,
                &transfer_root,
                &incoming_dir,
                &shared_dir,
                &shutdown,
                ready,
            )
        },
        |waiting| {
            // The failed future, runtime and profile lease have drained before this
            // wait. No host mutex is held while waiting or entering another attempt.
            host()
                .lock()
                .map_err(|_| anyhow::anyhow!("host state unavailable"))?
                .waiting_for_network = waiting;
            Ok(())
        },
    )
}

fn run_attempt(
    profile_dir: &std::path::Path,
    transfer_root: &std::path::Path,
    incoming_dir: &std::path::Path,
    shared_dir: &std::path::Path,
    shutdown: &ShutdownRequest,
    readiness_reported: &mut bool,
) -> Result<()> {
    let mut profile =
        DaemonProfile::load_hosted(profile_dir.into(), incoming_dir.into(), shared_dir.into())?;
    ensure_process_logging(profile.profile_io_dir())?;
    profile.host_transfer_root = Some(transfer_root.into());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (ready, readiness) = tokio::sync::oneshot::channel();
    let outcome = runtime.block_on(await_readiness(
        emulebb_daemon::run_hosted(profile, shutdown.subscribe(), ready),
        readiness,
        readiness_reported,
        |address| {
            let mut state = host()
                .lock()
                .map_err(|_| anyhow::anyhow!("host state unavailable"))?;
            state.address = Some(address.to_string());
            if state.phase == Phase::Starting {
                state.phase = Phase::Running;
            }
            Ok(())
        },
    ));
    // WHY: Tokio blocking work can outlive the daemon future. Drain the runtime
    // before retrying startup or publishing Stopped/releasing ownership.
    drop(runtime);
    outcome
}

async fn await_readiness(
    run: impl std::future::Future<Output = Result<()>>,
    mut readiness: tokio::sync::oneshot::Receiver<std::net::SocketAddr>,
    reported: &mut bool,
    ready: impl FnOnce(std::net::SocketAddr) -> Result<()>,
) -> Result<()> {
    tokio::pin!(run);
    tokio::select! {
        result = &mut run => {
            // WHY: the future can send readiness and fail in the same poll.
            // Such a failure is after readiness regardless of select order.
            *reported |= readiness.try_recv().is_ok();
            result
        },
        result = &mut readiness => {
            if let Ok(address) = result {
                *reported = true;
                ready(address)?;
            }
            run.await
        }
    }
}

fn prune_assets(profile_dir: &std::path::Path, current_web_root: &std::path::Path) -> Result<()> {
    let parent = profile_dir
        .parent()
        .context("profile has no parent")?
        .canonicalize()?;
    let current = current_web_root.canonicalize()?;
    ensure!(
        current.parent() == Some(parent.as_path()),
        "WebUI assets must belong to the application directory"
    );
    ensure!(
        current.join(".ready").is_file(),
        "current WebUI assets are not ready"
    );
    let mut versions = Vec::new();
    for entry in std::fs::read_dir(&parent)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(version) = name
            .to_str()
            .and_then(|name| name.strip_prefix("webui-"))
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        versions.push((version, entry.path()));
    }
    versions.sort_by_key(|item| std::cmp::Reverse(item.0));
    let mut retained_previous = false;
    for (_, path) in versions {
        if path == current {
            continue;
        }
        if !retained_previous {
            retained_previous = true;
            continue;
        }
        // WHY: source assets are disposable, but metadata/payloads are not.
        // Limit cleanup to real, directly owned version directories while the
        // profile lease excludes every running daemon, including other processes.
        ensure!(
            path.canonicalize()?.parent() == Some(parent.as_path()),
            "asset cleanup escaped application directory"
        );
        std::fs::remove_dir_all(path)?;
    }
    Ok(())
}

const _: jni::NativeMethod = native_method! {
    java_type = "org.emulebb.android.NativeBridge",
    extern fn request(payload: JString) -> JString,
};

fn request<'local>(
    env: &mut Env<'local>,
    _this: JObject<'local>,
    payload: JString<'local>,
) -> Result<JString<'local>, jni::errors::Error> {
    let input = payload.to_string();
    // The JNI macro catches panics and prevents unwinding into the JVM.
    let response = match serde_json::from_str::<Request>(&input)
        .map_err(|_| anyhow::anyhow!("invalid host request"))
        .and_then(handle)
    {
        Ok(data) => json!({"ok":true,"data":data}),
        Err(error) => json!({"ok":false,"error":format!("{error:#}")}),
    };
    JString::from_str(env, response.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_in_same_poll_as_readiness_is_after_startup() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let (ready, readiness) = tokio::sync::oneshot::channel();
        let mut reported = false;
        let outcome = runtime.block_on(await_readiness(
            async {
                ready.send("127.0.0.1:20017".parse().unwrap()).unwrap();
                Err(emulebb_daemon::NetworkStartupError::DefaultRouteUnavailable.into())
            },
            readiness,
            &mut reported,
            |_| panic!("terminal result must not publish Running"),
        ));
        assert!(reported);
        assert!(
            outcome
                .unwrap_err()
                .is::<emulebb_daemon::NetworkStartupError>()
        );
    }

    #[test]
    fn asset_cleanup_retains_current_previous_and_unrelated_data() {
        let root = tempfile::tempdir().unwrap();
        let profile = root.path().join("profile");
        for name in [
            "profile",
            "webui-1",
            "webui-2",
            "webui-3",
            "webui-custom",
            "payloads",
        ] {
            std::fs::create_dir(root.path().join(name)).unwrap();
        }
        std::fs::write(root.path().join("webui-3/.ready"), b"").unwrap();
        handle(Request::PruneAssets {
            profile_dir: profile,
            current_web_root: root.path().join("webui-3"),
        })
        .unwrap();
        assert!(!root.path().join("webui-1").exists());
        for name in ["profile", "webui-2", "webui-3", "webui-custom", "payloads"] {
            assert!(root.path().join(name).is_dir());
        }
    }

    #[test]
    fn private_host_protocol_rejects_unknown_fields_and_retired_commands() {
        assert!(serde_json::from_str::<Request>(r#"{"op":"status","api_key":"hidden"}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"op":"migrate"}"#).is_err());
        assert!(
            handle(Request::ReadSettings {
                profile_dir: "relative".into()
            })
            .is_err()
        );
    }

    #[test]
    fn external_link_validation_has_no_profile_or_runtime_side_effects() {
        let link = "ed2k://|file|Sample%20%26%20Guide.bin|42|00112233445566778899aabbccddeeff|/";
        assert_eq!(
            handle(Request::ValidateLink { link: link.into() }).unwrap(),
            json!(link)
        );
        for invalid in [
            "ed2k://|server|192.0.2.1|4661|/".to_string(),
            "ed2k://|file|Sample.bin|42|invalid|/".to_string(),
            "ed2k://|file|Sample.bin|invalid|00112233445566778899aabbccddeeff|/".to_string(),
            "ed2k://|file|Sample%0Abin|42|00112233445566778899aabbccddeeff|/".to_string(),
            format!(
                "ed2k://|file|{}|42|00112233445566778899aabbccddeeff|/",
                "A".repeat(2048)
            ),
        ] {
            assert!(handle(Request::ValidateLink { link: invalid }).is_err());
        }
        assert_eq!(handle(Request::Status {}).unwrap()["phase"], "Stopped");
    }
}
