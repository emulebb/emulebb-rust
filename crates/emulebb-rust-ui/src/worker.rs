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
                    let settings = fetch_app_settings(&client, &next_config).await?;
                    let search = fetch_latest_search(&client, &next_config)
                        .await
                        .ok()
                        .flatten();
                    Ok::<_, anyhow::Error>((snapshot, settings, search))
                });
                match result {
                    Ok((snapshot, settings, search)) => {
                        if let Some(search) = search {
                            active_search_id = Some(search.id.clone());
                            store_search(&cache, Some(search.clone()));
                            publish_search(&weak, search);
                        } else {
                            store_search(&cache, None);
                            publish_empty_search(&weak, "No active search");
                        }
                        store_app_settings(&cache, settings.clone());
                        publish_settings(
                            &weak,
                            settings,
                            "Settings loaded from daemon".to_string(),
                        );
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
            Some(UiCommand::SettingsReload) => runtime.block_on(async {
                let settings = fetch_app_settings(&client, &config_for_command).await?;
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((
                    snapshot,
                    None,
                    None,
                    Some((settings, "Settings reloaded".to_string())),
                ))
            }),
            Some(UiCommand::SettingsApply {
                form,
                settings_form,
            }) => runtime.block_on(async {
                let settings_baseline = match cached_app_settings(&cache) {
                    Some(settings) => settings,
                    None => fetch_app_settings(&client, &config_for_command).await?,
                };
                let baseline = cached_core_settings(&cache).unwrap_or_else(|| settings_baseline.core.clone());
                let core_patch = core_settings_update_from_form(&form, Some(&baseline))?;
                let mut settings_patch =
                    app_settings_update_from_form(&settings_form, &settings_baseline)?;
                let core_settings_changed = !core_settings_update_is_empty(&core_patch);
                let restart_required =
                    !emulebb_settings::app_settings_update_is_empty(&settings_patch);
                if core_settings_changed {
                    settings_patch.core = Some(core_patch);
                }
                let settings_changed = restart_required || core_settings_changed;
                let settings = if settings_changed {
                    update_app_settings(&client, &config_for_command, &settings_patch).await?
                } else {
                    settings_baseline
                };
                let status = if core_settings_changed || settings_changed {
                    if restart_required {
                        "Settings applied; restart daemon for bind, port, NAT, VPN, and filter changes"
                    } else {
                        "Settings applied"
                    }
                } else {
                    "No settings changes to apply"
                };
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((
                    snapshot,
                    None,
                    None,
                    Some((settings, status.to_string())),
                ))
            }),
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
                Ok((snapshot, None, None, None))
            }),
            Some(UiCommand::ServerAction { action, endpoint }) => runtime.block_on(async {
                match action.as_str() {
                    "connect-selected" => {
                        let endpoint = selected_endpoint(&endpoint)?;
                        post_operation(
                            &client,
                            &config_for_command,
                            &format!("servers/{endpoint}/operations/connect"),
                        )
                        .await?;
                    }
                    "disconnect" => {
                        post_operation(
                            &client,
                            &config_for_command,
                            &format!("servers/operations/{action}"),
                        )
                        .await?;
                    }
                    _ => anyhow::bail!("unsupported server action: {action}"),
                }
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((snapshot, None, None, None))
            }),
            Some(UiCommand::ServerAdd { form }) => runtime.block_on(async {
                let request = server_create_request(form)?;
                let _ = create_server(&client, &config_for_command, &request).await?;
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((snapshot, None, None, None))
            }),
            Some(UiCommand::ServerUpdate { endpoint, form }) => runtime.block_on(async {
                let endpoint = selected_endpoint(&endpoint)?;
                let request = server_update_request(form);
                let _ = update_server(&client, &config_for_command, &endpoint, &request).await?;
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((snapshot, None, None, None))
            }),
            Some(UiCommand::ServerDelete { endpoint }) => runtime.block_on(async {
                let endpoint = selected_endpoint(&endpoint)?;
                delete_server(&client, &config_for_command, &endpoint).await?;
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((snapshot, None, None, None))
            }),
            Some(UiCommand::ServerImport { url }) => runtime.block_on(async {
                if url.trim().is_empty() {
                    anyhow::bail!("enter a server.met URL before importing");
                }
                import_servers_url(&client, &config_for_command, url).await?;
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((snapshot, None, None, None))
            }),
            Some(UiCommand::KadAction { action }) => runtime.block_on(async {
                match action.as_str() {
                    "start" | "stop" | "bootstrap" | "recheck-firewall" => {
                        kad_operation(&client, &config_for_command, &action).await?;
                    }
                    _ => anyhow::bail!("unsupported Kad action: {action}"),
                }
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((snapshot, None, None, None))
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
                Ok((snapshot, Some(search), Some(search_id), None))
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
                Ok((snapshot, Some(search), Some(search_id), None))
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
                Ok((snapshot, search, Some(search_id), None))
            }),
            Some(UiCommand::Refresh) => runtime.block_on(async {
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
                Ok((snapshot, search, next_search_id, None))
            }),
            None => runtime.block_on(async {
                let search = match active_search_id_for_poll.as_deref() {
                    Some(search_id) => fetch_search(&client, &config_for_command, search_id)
                        .await
                        .ok(),
                    None => None,
                };
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((snapshot, search, active_search_id_for_poll, None))
            }),
            Some(UiCommand::Connect(_)) => unreachable!("connect commands are handled separately"),
        };
        match result {
            Ok((snapshot, search, next_active_search_id, settings_update)) => {
                consecutive_failures = 0;
                if let Some(search_id) = next_active_search_id {
                    active_search_id = Some(search_id);
                }
                if let Some(search) = search {
                    store_search(&cache, Some(search.clone()));
                    publish_search(&weak, search);
                }
                if let Some((settings, status)) = settings_update {
                    store_app_settings(&cache, settings.clone());
                    publish_settings(&weak, settings, status);
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

fn selected_endpoint(endpoint: &str) -> Result<String> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        anyhow::bail!("select a server before running this action");
    }
    Ok(endpoint.to_string())
}

fn server_create_request(form: ServerForm) -> Result<ServerCreateRequest> {
    let address = form.address.trim().to_string();
    if address.is_empty() {
        anyhow::bail!("enter a server address");
    }
    let port = parse_u16(&form.port, "server port")?;
    Ok(ServerCreateRequest {
        address,
        port,
        name: optional_string(form.name),
        priority: optional_string(form.priority),
        static_server: Some(form.static_server),
        connect: Some(form.connect),
    })
}

fn server_update_request(form: ServerForm) -> ServerUpdateRequest {
    ServerUpdateRequest {
        name: optional_string(form.name),
        priority: optional_string(form.priority),
        static_server: Some(form.static_server),
        enabled: Some(form.enabled),
    }
}

fn core_settings_update_from_form(
    form: &CoreSettingsForm,
    baseline: Option<&CoreSettings>,
) -> Result<CoreSettingsUpdate> {
    let next = CoreSettings {
        upload_limit_ki_bps: parse_u32_core_setting(
            FIELD_UPLOAD_LIMIT_KIBPS,
            &form.upload_limit_ki_bps,
        )?,
        download_limit_ki_bps: parse_u32_core_setting(
            FIELD_DOWNLOAD_LIMIT_KIBPS,
            &form.download_limit_ki_bps,
        )?,
        max_connections: parse_u32_core_setting(FIELD_MAX_CONNECTIONS, &form.max_connections)?,
        max_connections_per_five_seconds: parse_u32_core_setting(
            FIELD_MAX_CONNECTIONS_PER_FIVE_SECONDS,
            &form.max_connections_per_five_seconds,
        )?,
        max_sources_per_file: parse_u32_core_setting(
            FIELD_MAX_SOURCES_PER_FILE,
            &form.max_sources_per_file,
        )?,
        upload_client_data_rate: parse_u32_core_setting(
            FIELD_UPLOAD_CLIENT_DATA_RATE,
            &form.upload_client_data_rate,
        )?,
        max_upload_slots: parse_u32_core_setting(FIELD_MAX_UPLOAD_SLOTS, &form.max_upload_slots)?,
        upload_slot_elastic_percent: parse_u32_core_setting(
            FIELD_UPLOAD_SLOT_ELASTIC_PERCENT,
            &form.upload_slot_elastic_percent,
        )?,
        queue_size: parse_u32_core_setting(FIELD_QUEUE_SIZE, &form.queue_size)?,
        auto_connect: form.auto_connect,
        reconnect: form.reconnect,
        credit_system: form.credit_system,
        safe_server_connect: form.safe_server_connect,
        add_servers_from_server: form.add_servers_from_server,
        network_kademlia: form.network_kademlia,
        network_ed2k: form.network_ed2k,
    };
    Ok(changed_core_settings_update(&next, baseline))
}

fn app_settings_update_from_form(
    form: &AppSettingsForm,
    baseline: &AppSettings,
) -> Result<AppSettingsUpdate> {
    let mut next = baseline.clone();
    next.daemon.incoming_dir = optional_path_buf(&form.incoming_dir);
    next.daemon.p2p_bind_ip = optional_ipv4(&form.p2p_bind_ip, "P2P bind IP")?;
    next.daemon.p2p_bind_interface = optional_string(form.p2p_bind_interface.clone());
    next.ed2k.listen_port = optional_u16(&form.ed2k_listen_port, "eD2K listen port")?;
    next.ed2k.obfuscation_enabled = form.ed2k_obfuscation_enabled;
    next.ed2k.connect_timeout_secs =
        parse_u64(&form.ed2k_connect_timeout_secs, "eD2K connect timeout")?;
    next.ed2k.reconnect_interval_secs = parse_u64(
        &form.ed2k_reconnect_interval_secs,
        "eD2K reconnect interval",
    )?;
    next.ed2k.enable_udp_reask = form.ed2k_enable_udp_reask;
    next.ed2k.publish_emule_rust_identity = form.ed2k_publish_emule_rust_identity;
    next.kad.listen_port = optional_u16(&form.kad_listen_port, "Kad listen port")?;
    next.kad.bootstrap_min_routing_contacts = parse_usize(
        &form.kad_bootstrap_min_routing_contacts,
        "Kad bootstrap minimum routing contacts",
    )?;
    next.kad.publish_shared_files_enabled = form.kad_publish_shared_files_enabled;
    next.kad.routing_maintenance_enabled = form.kad_routing_maintenance_enabled;
    next.nat.enabled = form.nat_enabled;
    next.nat.require_initial_mapping = form.nat_require_initial_mapping;
    next.nat.bind_ip = optional_string(form.nat_bind_ip.clone());
    next.nat.external_ip_override = optional_string(form.nat_external_ip_override.clone());
    next.vpn_guard.enabled = form.vpn_guard_enabled;
    next.vpn_guard.mode = form.vpn_guard_mode.trim().to_string();
    next.vpn_guard.allowed_public_ip_cidrs =
        form.vpn_guard_allowed_public_ip_cidrs.trim().to_string();
    next.ip_filter.enabled = form.ip_filter_enabled;
    next.ip_filter.path = optional_path_buf(&form.ip_filter_path);
    next.ip_filter.level = parse_u32(&form.ip_filter_level, "IP filter level")?;

    Ok(AppSettingsUpdate {
        core: None,
        daemon: changed_section(&next.daemon, &baseline.daemon).map(Into::into),
        ed2k: changed_section(&next.ed2k, &baseline.ed2k).map(Into::into),
        kad: changed_section(&next.kad, &baseline.kad).map(Into::into),
        nat: changed_section(&next.nat, &baseline.nat).map(Into::into),
        vpn_guard: changed_section(&next.vpn_guard, &baseline.vpn_guard).map(Into::into),
        ip_filter: changed_section(&next.ip_filter, &baseline.ip_filter).map(Into::into),
    })
}

fn parse_u16(value: &str, name: &str) -> Result<u16> {
    value
        .trim()
        .parse::<u16>()
        .with_context(|| format!("{name} must be a TCP port"))
}

fn optional_u16(value: &str, name: &str) -> Result<Option<u16>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse::<u16>()
        .map(Some)
        .with_context(|| format!("{name} must be a TCP port"))
}

fn parse_u64(value: &str, name: &str) -> Result<u64> {
    value
        .trim()
        .parse::<u64>()
        .with_context(|| format!("{name} must be an unsigned number"))
}

fn parse_usize(value: &str, name: &str) -> Result<usize> {
    value
        .trim()
        .parse::<usize>()
        .with_context(|| format!("{name} must be an unsigned number"))
}

fn parse_u32(value: &str, name: &str) -> Result<u32> {
    value
        .trim()
        .parse::<u32>()
        .with_context(|| format!("{name} must be an unsigned number"))
}

fn optional_ipv4(value: &str, name: &str) -> Result<Option<std::net::Ipv4Addr>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse::<std::net::Ipv4Addr>()
        .map(Some)
        .with_context(|| format!("{name} must be an IPv4 address"))
}

fn optional_path_buf(value: &str) -> Option<std::path::PathBuf> {
    let value = value.trim();
    (!value.is_empty()).then(|| std::path::PathBuf::from(value))
}

fn optional_string(value: String) -> Option<String> {
    let value = value.trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn changed_section<T>(next: &T, baseline: &T) -> Option<T>
where
    T: Clone + PartialEq,
{
    (next != baseline).then(|| next.clone())
}
