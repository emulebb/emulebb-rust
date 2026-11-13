//! Narrow application-host boundary; the Android shell owns no client settings.

use std::{
    path::PathBuf,
    sync::{Mutex, OnceLock},
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

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", deny_unknown_fields)]
enum Request {
    ReadSettings {
        profile_dir: PathBuf,
    },
    WriteSettings {
        profile_dir: PathBuf,
        bind_addr: String,
        api_key: String,
        web_root_dir: PathBuf,
    },
    Start {
        profile_dir: PathBuf,
        transfer_root: PathBuf,
        incoming_dir: PathBuf,
    },
    Stop {},
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
}

fn host() -> &'static Mutex<Host> {
    static HOST: OnceLock<Mutex<Host>> = OnceLock::new();
    HOST.get_or_init(Mutex::default)
}

fn handle(request: Request) -> Result<Value> {
    match request {
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
        } => {
            ensure!(
                profile_dir.is_absolute()
                    && transfer_root.is_absolute()
                    && incoming_dir.is_absolute(),
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
            let worker = std::thread::Builder::new().name("emulebb-android".into()).spawn(move || {
                let outcome = std::panic::catch_unwind(|| -> Result<()> {
                    if shutdown.subscribe().is_requested() { return Ok(()); }
                    let mut profile = DaemonProfile::load(Some(profile_dir))?;
                    profile.host_transfer_root = Some(transfer_root);
                    if profile.incoming_dir.is_none() { profile.incoming_dir = Some(incoming_dir); }
                    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
                    let outcome = runtime.block_on(async {
                        let (ready, mut readiness) = tokio::sync::oneshot::channel();
                        let run = emulebb_daemon::run_hosted(profile, shutdown.subscribe(), ready);
                        tokio::pin!(run);
                        tokio::select! {
                            result = &mut run => result,
                            result = &mut readiness => {
                                if let Ok(address) = result {
                                    let mut state = host().lock().map_err(|_| anyhow::anyhow!("host state unavailable"))?;
                                    state.address = Some(address.to_string());
                                    if state.phase == Phase::Starting { state.phase = Phase::Running; }
                                }
                                run.await
                            }
                        }
                    });
                    // WHY: Tokio blocking work can outlive the daemon future. Drain
                    // the application runtime before publishing Stopped/releasing ownership.
                    drop(runtime);
                    outcome
                });
                if let Ok(mut state) = host().lock() {
                    match outcome {
                        Ok(Ok(())) => { state.phase = Phase::Stopped; state.error = None; }
                        Ok(Err(error)) => { state.phase = Phase::Failed; state.error = Some(format!("{error:#}")); }
                        Err(_) => { state.phase = Phase::Failed; state.error = Some("native runtime failed".into()); }
                    }
                    state.shutdown = None;
                    state.address = None;
                }
            });
            match worker {
                Ok(worker) => state.worker = Some(worker),
                Err(error) => {
                    state.phase = Phase::Failed;
                    state.shutdown = None;
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
            Ok(Value::Null)
        }
        Request::Status {} => {
            let state = host()
                .lock()
                .map_err(|_| anyhow::anyhow!("host state unavailable"))?;
            Ok(json!({"phase":state.phase,"error":state.error,"address":state.address}))
        }
    }
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
}
