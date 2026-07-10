use super::*;

pub(crate) fn parse_server_endpoint(endpoint: &str) -> Result<(String, u16)> {
    let Some((address, port)) = endpoint.rsplit_once(':') else {
        anyhow::bail!("server id must use address:port");
    };
    ensure!(
        !address.trim().is_empty(),
        "server id must use address:port"
    );
    let port = port
        .parse::<u16>()
        .with_context(|| format!("invalid server endpoint port in {endpoint}"))?;
    ensure!(port != 0, "port must be in the range 1..65535");
    Ok((address.to_string(), port))
}

fn is_retryable_direct_download_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|inner| inner.kind() == std::io::ErrorKind::ConnectionRefused)
    })
}

#[allow(clippy::cognitive_complexity)]
pub(crate) async fn run_ed2k_direct_downloads<DownloadFn, DownloadFuture>(
    options: DirectDownloadOptions,
    download_peer: DownloadFn,
) -> Result<DirectDownloadOutcome>
where
    DownloadFn: Fn(
            Ipv4Addr,
            Ed2kFoundSource,
            Ed2kHelloIdentity,
            Arc<Ed2kSecureIdent>,
            Arc<Ed2kTransferRuntime>,
            String,
            u64,
            Duration,
        ) -> DownloadFuture
        + Clone
        + Send
        + Sync
        + 'static,
    DownloadFuture: Future<Output = Result<Ed2kPeerDownloadOutcome>> + Send + 'static,
{
    let DirectDownloadOptions {
        bind_ip,
        hello_identity,
        secure_ident,
        transfer_runtime,
        file_hash_hex,
        file_name,
        file_size,
        sources,
        connect_timeout,
        max_parallel_download_peers,
    } = options;
    let max_parallel_download_peers = max_parallel_download_peers.max(1);
    let retry_deadline =
        if !sources.is_empty() && sources.iter().all(|source| source.ip.is_loopback()) {
            Some(tokio::time::Instant::now() + Duration::from_secs(360))
        } else {
            None
        };
    let retry_sources = sources;
    let mut retry_round = 0u32;
    let mut last_error: Option<anyhow::Error> = None;
    // Endpoints that detached onto UDP reask across all retry rounds; their leases
    // are kept (not released) so the next cycle does not re-TCP them.
    let mut detached_reask_endpoints: Vec<(Ipv4Addr, u16)> = Vec::new();
    // Sources that reported No Needed Parts; the driver runs the A4AF-lite swap
    // on each after the round (move to another wanted file the peer serves) and
    // then NNP-holds each on this file for the doubled 58-minute reask cycle
    // (oracle DS_NONEEDEDPARTS). Kept across retry rounds.
    let mut no_needed_parts_sources: Vec<Ed2kFoundSource> = Vec::new();
    // Sources that answered OP_FILEREQANSNOFIL (or AICH-mismatch-as-FNF); the
    // driver dead-lists + drops each after the round (oracle
    // ListenSocket.cpp:645-661). Kept across retry rounds.
    let mut file_not_found_sources: Vec<Ed2kFoundSource> = Vec::new();

    loop {
        let mut accepted_incomplete_peers = 0u32;
        let mut retryable_error_seen = false;
        let mut pending_sources = VecDeque::from(retry_sources.clone());
        let mut active_downloads = JoinSet::new();
        let spawn_context = DirectDownloadSpawnContext {
            bind_ip,
            hello_identity,
            secure_ident: &secure_ident,
            transfer_runtime: &transfer_runtime,
            file_hash_hex: &file_hash_hex,
            file_name: &file_name,
            file_size,
            connect_timeout,
            retry_round,
            download_peer: &download_peer,
        };

        spawn_pending_ed2k_direct_downloads(
            &mut active_downloads,
            &mut pending_sources,
            &spawn_context,
            max_parallel_download_peers,
        );

        while let Some(joined) = active_downloads.join_next().await {
            // Release the global connection budget slot this finished download
            // held (acquired in spawn_pending_ed2k_direct_downloads) so the next
            // source can claim it.
            transfer_runtime.release_source_connection();
            let (peer_addr, source, result) = match joined {
                Ok(joined) => joined,
                Err(join_error) => {
                    // The worker panicked. Returning here without draining the
                    // remaining in-flight tasks would leak their connection-budget
                    // slots permanently (their release_source_connection never
                    // runs), eventually stalling the whole download subsystem.
                    // Abort and drain the rest, releasing one slot per task.
                    active_downloads.abort_all();
                    while active_downloads.join_next().await.is_some() {
                        transfer_runtime.release_source_connection();
                    }
                    return Err(anyhow::Error::new(join_error)
                        .context("ED2K direct download worker panicked"));
                }
            };
            match result {
                Ok(Ed2kPeerDownloadOutcome::Completed) => {
                    let manifest = transfer_runtime.manifest(&file_hash_hex).await?;
                    tracing::info!(
                        "ED2K direct download peer completed file_hash={} peer={} manifest_completed={} verified_ranges={} file_size={}",
                        file_hash_hex,
                        peer_addr,
                        manifest.completed,
                        manifest.verified_ranges.len(),
                        manifest.file_size
                    );
                    if manifest.completed {
                        active_downloads.abort_all();
                        // Release the budget slot held by each aborted download.
                        while active_downloads.join_next().await.is_some() {
                            transfer_runtime.release_source_connection();
                        }
                        return Ok(DirectDownloadOutcome {
                            completed: true,
                            accepted_incomplete_peers,
                            last_error: last_error
                                .as_ref()
                                .map(|error| anyhow::anyhow!(error.to_string())),
                            detached_reask_endpoints: detached_reask_endpoints.clone(),
                            no_needed_parts_sources: no_needed_parts_sources.clone(),
                            file_not_found_sources: file_not_found_sources.clone(),
                        });
                    }
                }
                Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete) => {
                    accepted_incomplete_peers = accepted_incomplete_peers.saturating_add(1);
                    tracing::info!(
                        "ED2K direct download peer accepted incomplete file_hash={} peer={}",
                        file_hash_hex,
                        peer_addr
                    );
                }
                Ok(Ed2kPeerDownloadOutcome::QueuedDetachedForUdpReask) => {
                    // The source detached its TCP socket onto the UDP reask loop,
                    // which now keeps its queue slot warm and re-engages over TCP
                    // on UDP failure. Count it like an accepted-incomplete peer.
                    accepted_incomplete_peers = accepted_incomplete_peers.saturating_add(1);
                    detached_reask_endpoints.push(source_endpoint_key(&source));
                    tracing::info!(
                        "ED2K direct download peer detached to UDP reask file_hash={} peer={}",
                        file_hash_hex,
                        peer_addr
                    );
                }
                Ok(Ed2kPeerDownloadOutcome::NoNeededParts) => {
                    // No Needed Parts for this file (eMuleBB DS_NONEEDEDPARTS). The
                    // driver runs the A4AF-lite SwapToAnotherFile afterwards (this
                    // source is moved to another wanted file it serves, if any) and
                    // then NNP-holds the source on this file for the doubled
                    // 58-minute reask cycle instead of dropping it.
                    no_needed_parts_sources.push(source.clone());
                    tracing::info!(
                        "ED2K direct download peer reported no needed parts file_hash={} peer={}",
                        file_hash_hex,
                        peer_addr
                    );
                }
                Ok(Ed2kPeerDownloadOutcome::FileNotFound) => {
                    // OP_FILEREQANSNOFIL (or AICH-mismatch-as-FNF): the driver
                    // dead-lists the (source, file) pair for 45 minutes and drops
                    // the source afterwards (oracle ListenSocket.cpp:645-661).
                    file_not_found_sources.push(source.clone());
                    tracing::info!(
                        "ED2K direct download peer answered file-not-found file_hash={} peer={}",
                        file_hash_hex,
                        peer_addr
                    );
                }
                Err(error) => {
                    retryable_error_seen |= is_retryable_direct_download_error(&error);
                    tracing::warn!(
                        "ED2K direct download peer failed file_hash={} peer={}: {error}",
                        file_hash_hex,
                        peer_addr
                    );
                    last_error = Some(error);
                }
            }

            spawn_pending_ed2k_direct_downloads(
                &mut active_downloads,
                &mut pending_sources,
                &spawn_context,
                max_parallel_download_peers,
            );
        }

        let outcome = DirectDownloadOutcome {
            completed: transfer_runtime.manifest(&file_hash_hex).await?.completed,
            accepted_incomplete_peers,
            last_error: last_error
                .as_ref()
                .map(|error| anyhow::anyhow!(error.to_string())),
            detached_reask_endpoints: detached_reask_endpoints.clone(),
            no_needed_parts_sources: no_needed_parts_sources.clone(),
            file_not_found_sources: file_not_found_sources.clone(),
        };
        if outcome.completed
            || outcome.accepted_incomplete_peers != 0
            || !outcome.no_needed_parts_sources.is_empty()
            || !outcome.file_not_found_sources.is_empty()
        {
            return Ok(outcome);
        }

        let Some(deadline) = retry_deadline else {
            return Ok(outcome);
        };
        if !retryable_error_seen || tokio::time::Instant::now() >= deadline {
            return Ok(outcome);
        }

        retry_round = retry_round.saturating_add(1);
        tracing::info!(
            "ED2K direct download retrying loopback sources file_hash={} retry_round={}",
            file_hash_hex,
            retry_round
        );
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

fn spawn_pending_ed2k_direct_downloads<DownloadFn, DownloadFuture>(
    active_downloads: &mut JoinSet<DirectDownloadJoin>,
    pending_sources: &mut VecDeque<Ed2kFoundSource>,
    context: &DirectDownloadSpawnContext<'_, DownloadFn>,
    max_parallel_download_peers: usize,
) where
    DownloadFn: Fn(
            Ipv4Addr,
            Ed2kFoundSource,
            Ed2kHelloIdentity,
            Arc<Ed2kSecureIdent>,
            Arc<Ed2kTransferRuntime>,
            String,
            u64,
            Duration,
        ) -> DownloadFuture
        + Clone
        + Send
        + Sync
        + 'static,
    DownloadFuture: Future<Output = Result<Ed2kPeerDownloadOutcome>> + Send + 'static,
{
    while active_downloads.len() < max_parallel_download_peers {
        let Some(source) = pending_sources.pop_front() else {
            break;
        };
        // Global connection budget (eMule CListenSocket::TooManySockets): the
        // shared coordinator caps concurrent outgoing source connections and
        // the new-connection per-5s rate across ALL transfers. When no slot is
        // available, leave the source pending (push it back) for the next cycle
        // rather than dropping it, and stop spawning this round.
        let budget = context
            .transfer_runtime
            .try_acquire_source_connection_detailed();
        crate::diag_sched::source_conn_budget(budget, context.file_hash_hex, &source);
        if !budget.admitted {
            pending_sources.push_front(source);
            tracing::debug!(
                "ED2K direct download deferred by connection budget file_hash={} active={}",
                context.file_hash_hex,
                active_downloads.len()
            );
            break;
        }
        let transfer_runtime = Arc::clone(context.transfer_runtime);
        let secure_ident = Arc::clone(context.secure_ident);
        let download_peer = context.download_peer.clone();
        let file_name = context.file_name.to_string();
        let file_hash_hex = context.file_hash_hex.to_string();
        let peer_addr = SocketAddr::new(IpAddr::V4(source.ip), source.tcp_port);
        tracing::info!(
            "ED2K direct download attempt file_hash={} peer={} client_id={} obfuscated={} has_user_hash={} retry_round={}",
            file_hash_hex,
            peer_addr,
            source.client_id,
            source.obfuscated,
            source.user_hash.is_some(),
            context.retry_round
        );
        let bind_ip = context.bind_ip;
        let hello_identity = context.hello_identity;
        let file_size = context.file_size;
        let connect_timeout = context.connect_timeout;
        active_downloads.spawn(async move {
            let result = download_peer(
                bind_ip,
                source.clone(),
                hello_identity,
                secure_ident,
                transfer_runtime,
                file_name,
                file_size,
                connect_timeout,
            )
            .await;
            (peer_addr, source, result)
        });
    }
}
