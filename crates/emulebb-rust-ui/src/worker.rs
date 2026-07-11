use super::*;

pub(super) fn worker_loop(
    weak: slint::Weak<MainWindow>,
    rx: mpsc::Receiver<UiCommand>,
    poll_interval: Duration,
    cache: Arc<Mutex<DataCache>>,
) {
    let Ok(runtime) = tokio::runtime::Runtime::new() else {
        publish_error(&weak, "Failed to start async runtime".to_string(), true);
        return;
    };
    let client = Client::new();
    let mut config: Option<ConnectionConfig> = None;
    let mut active_search_id: Option<String> = None;
    let mut consecutive_failures = 0_u32;

    loop {
        let command = match rx.recv_timeout(poll_interval) {
            Ok(command) => Some(command),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => break,
        };

        let command = match command {
            Some(UiCommand::Connect(next_config)) => {
                config = Some(next_config.clone());
                active_search_id = None;
                consecutive_failures = 0;
                publish_refreshing(&weak, true);
                let result = runtime.block_on(async {
                    let snapshot = fetch_snapshot(&client, &next_config).await?;
                    let search = fetch_latest_search(&client, &next_config)
                        .await
                        .ok()
                        .flatten();
                    Ok::<_, anyhow::Error>((snapshot, search))
                });
                match result {
                    Ok((snapshot, search)) => {
                        if let Some(search) = search {
                            active_search_id = Some(search.id.clone());
                            store_search(&cache, Some(search.clone()));
                            publish_search(&weak, search);
                        } else {
                            store_search(&cache, None);
                            publish_empty_search(&weak, "No active search");
                        }
                        store_snapshot(&cache, snapshot.clone());
                        publish_snapshot(&weak, snapshot);
                    }
                    Err(error) => {
                        consecutive_failures += 1;
                        publish_poll_error(&weak, error.to_string(), consecutive_failures, true);
                    }
                }
                publish_refreshing(&weak, false);
                continue;
            }
            other => other,
        };

        let Some(config_for_command) = config.clone() else {
            continue;
        };

        let visible_refresh = command.is_some();
        if visible_refresh {
            publish_refreshing(&weak, true);
        }

        let active_search_id_for_poll = active_search_id.clone();
        let result = match command {
            Some(UiCommand::TransferAction { hash, action }) => runtime.block_on(async {
                if hash.trim().is_empty() {
                    anyhow::bail!("select a transfer before running an action");
                }
                post_operation(
                    &client,
                    &config_for_command,
                    &format!("transfers/{hash}/operations/{action}"),
                )
                .await?;
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((snapshot, None, None))
            }),
            Some(UiCommand::ServerAction { action }) => runtime.block_on(async {
                post_operation(
                    &client,
                    &config_for_command,
                    &format!("servers/operations/{action}"),
                )
                .await?;
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((snapshot, None, None))
            }),
            Some(UiCommand::SearchStart {
                query,
                method,
                file_type,
            }) => runtime.block_on(async {
                let created =
                    create_search(&client, &config_for_command, query, method, file_type).await?;
                let search_id = created.id.clone();
                let search = fetch_search(&client, &config_for_command, &search_id)
                    .await
                    .unwrap_or(created);
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((snapshot, Some(search), Some(search_id)))
            }),
            Some(UiCommand::SearchRefresh) => runtime.block_on(async {
                let search = match active_search_id_for_poll {
                    Some(search_id) => {
                        fetch_search(&client, &config_for_command, &search_id).await?
                    }
                    None => fetch_latest_search(&client, &config_for_command)
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("start a search before polling"))?,
                };
                let search_id = search.id.clone();
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((snapshot, Some(search), Some(search_id)))
            }),
            Some(UiCommand::SearchDownload {
                search_id,
                hash,
                paused,
            }) => runtime.block_on(async {
                if search_id.trim().is_empty() || hash.trim().is_empty() {
                    anyhow::bail!("select a search result before downloading");
                }
                download_search_result(&client, &config_for_command, &search_id, &hash, paused)
                    .await?;
                let search = fetch_search(&client, &config_for_command, &search_id)
                    .await
                    .ok();
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((snapshot, search, Some(search_id)))
            }),
            Some(UiCommand::Refresh) | None => runtime.block_on(async {
                let search = match active_search_id_for_poll.as_deref() {
                    Some(search_id) => fetch_search(&client, &config_for_command, search_id)
                        .await
                        .ok(),
                    None => fetch_latest_search(&client, &config_for_command)
                        .await
                        .ok()
                        .flatten(),
                };
                let next_search_id = active_search_id_for_poll.or_else(|| {
                    search
                        .as_ref()
                        .filter(|search| !search.id.trim().is_empty())
                        .map(|search| search.id.clone())
                });
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((snapshot, search, next_search_id))
            }),
            Some(UiCommand::Connect(_)) => unreachable!("connect commands are handled separately"),
        };
        match result {
            Ok((snapshot, search, next_active_search_id)) => {
                consecutive_failures = 0;
                if let Some(search_id) = next_active_search_id {
                    active_search_id = Some(search_id);
                }
                if let Some(search) = search {
                    store_search(&cache, Some(search.clone()));
                    publish_search(&weak, search);
                }
                store_snapshot(&cache, snapshot.clone());
                publish_snapshot(&weak, snapshot);
            }
            Err(error) => {
                consecutive_failures += 1;
                publish_poll_error(
                    &weak,
                    error.to_string(),
                    consecutive_failures,
                    visible_refresh,
                );
            }
        }

        if visible_refresh {
            publish_refreshing(&weak, false);
        }
    }
}
