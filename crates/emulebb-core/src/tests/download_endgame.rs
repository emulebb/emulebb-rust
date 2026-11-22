//! Real Core/Native endgame competition through two gated seed connections.
use super::*;
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::{FramedRead, LengthDelimitedCodec};

// Standard eMule block geometry; the Native allocator's constant is private.
const BLOCK: usize = 184_320;
const SIZE: usize = 8 * BLOCK + 1024;
const PREFIX: usize = 7 * BLOCK - 256;
const TAIL: usize = 8 * BLOCK;
const OP_SENDINGPART: u8 = 0x46;

#[derive(Clone, Copy)]
struct Geometry {
    size: usize,
    prefix: usize,
    replacement_start: usize,
    tail: usize,
    served: usize,
}

impl Geometry {
    const COMPLETE: Self = Self {
        size: SIZE,
        prefix: PREFIX,
        replacement_start: 7 * BLOCK,
        tail: TAIL,
        served: SIZE,
    };
    const PARTIAL: Self = Self {
        size: emulebb_ed2k::ed2k_transfer::ED2K_PART_SIZE as usize + 1024,
        prefix: 51 * BLOCK - 256,
        replacement_start: 51 * BLOCK,
        tail: 52 * BLOCK,
        served: emulebb_ed2k::ed2k_transfer::ED2K_PART_SIZE as usize,
    };
}

fn frames(
    read: tokio::net::tcp::OwnedReadHalf,
) -> FramedRead<tokio::net::tcp::OwnedReadHalf, LengthDelimitedCodec> {
    FramedRead::new(
        read,
        LengthDelimitedCodec::builder()
            .little_endian()
            .length_field_offset(1)
            .length_field_length(4)
            .length_adjustment(5)
            .num_skip(0)
            .max_frame_length(2_000_005)
            .new_codec(),
    )
}

fn payload_range(frame: &[u8]) -> Option<(usize, usize)> {
    if frame.get(5) != Some(&OP_SENDINGPART) {
        return None;
    }
    assert!(frame.len() >= 30);
    assert_eq!(frame[0], 0xe3);
    let start = u32::from_le_bytes(frame[22..26].try_into().unwrap()) as usize;
    let end = u32::from_le_bytes(frame[26..30].try_into().unwrap()) as usize;
    assert_eq!(
        end - start,
        frame.len() - 30,
        "seed frame must carry its declared range"
    );
    Some((start, end))
}

async fn relay_to_seed(
    client: TcpStream,
    backend: SocketAddr,
) -> (
    tokio::net::tcp::OwnedWriteHalf,
    FramedRead<tokio::net::tcp::OwnedReadHalf, LengthDelimitedCodec>,
    tokio::task::JoinHandle<std::io::Result<&'static str>>,
) {
    let seed = TcpStream::connect(backend).await.unwrap();
    let (mut client_read, client_write) = client.into_split();
    let (seed_read, mut seed_write) = seed.into_split();
    let forward = tokio::spawn(async move {
        let mut buffer = [0u8; 8192];
        loop {
            // WHY: a failed upstream write does not prove the receiver closed.
            // Only EOF/reset on the receiver's read side satisfies this barrier.
            let length = match client_read.read(&mut buffer).await {
                Ok(0) => return Ok("receiver EOF"),
                Ok(length) => length,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    return Ok(match error.kind() {
                        std::io::ErrorKind::ConnectionReset => "receiver reset",
                        _ => "receiver aborted",
                    });
                }
                Err(error) => {
                    return Err(std::io::Error::new(
                        error.kind(),
                        format!("receiver read failed: {error}"),
                    ));
                }
            };
            seed_write
                .write_all(&buffer[..length])
                .await
                .map_err(|error| {
                    std::io::Error::new(error.kind(), format!("seed write failed: {error}"))
                })?;
        }
    });
    (client_write, frames(seed_read), forward)
}

async fn assert_peer_closed(forward: tokio::task::JoinHandle<std::io::Result<&'static str>>) {
    forward
        .await
        .unwrap()
        .expect("receiver EOF/reset must end forwarding");
}

/// Obtain the prefix through the real downloader, with a valid final shortened
/// data packet and then EOF. No manifest or byte-presence state is fabricated.
async fn prefix_relay(listener: TcpListener, backend: SocketAddr, prefix: usize) {
    let (client, _) = listener.accept().await.unwrap();
    let (mut writer, mut incoming, forward) = relay_to_seed(client, backend).await;
    let mut forwarded = 0;
    let mut next_progress = 0;
    while let Some(frame) = incoming.next().await {
        let mut frame = frame.unwrap_or_else(|error| {
            panic!("seed frame failed after {forwarded}/{prefix} bytes: {error}")
        });
        if let Some((start, end)) = payload_range(&frame) {
            if end >= next_progress {
                eprintln!("endgame prefix reached {end}, target={prefix}");
                next_progress = end + 1024 * 1024;
            }
            assert_eq!(start, forwarded);
            if end >= prefix {
                let keep = prefix - start;
                frame.truncate(30 + keep);
                frame[26..30].copy_from_slice(&(prefix as u32).to_le_bytes());
                let length = (frame.len() - 5) as u32;
                frame[1..5].copy_from_slice(&length.to_le_bytes());
                writer.write_all(&frame).await.unwrap();
                writer.shutdown().await.unwrap();
                assert_peer_closed(forward).await;
                return;
            }
            forwarded = end;
        } else {
            eprintln!(
                "endgame prefix control opcode={:02x}, forwarded={forwarded}",
                frame[5]
            );
        }
        writer.write_all(&frame).await.unwrap();
    }
    // WHY: upstream EOF can follow receiver shutdown. Preserve the exact byte
    // boundary and forwarding result instead of mistaking the last progress log
    // for the close offset or assuming the seed initiated the close.
    let receiver = if forward.is_finished() {
        format!("{:?}", forward.await)
    } else {
        "forwarding task still pending when seed EOF was observed".into()
    };
    panic!("seed EOF after {forwarded}/{prefix} bytes; receiver forwarding: {receiver}");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Original,
    Replacement,
}
#[derive(Debug, PartialEq, Eq)]
enum Event {
    Warmup(Role),
    Tail(Role),
    Truncated(Role),
}

async fn expect_event(received: &mut mpsc::Receiver<Event>, expected: Event) {
    let event = tokio::time::timeout(Duration::from_secs(8), received.recv())
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {expected:?}"));
    assert_eq!(event, Some(expected));
}
struct Gate {
    geometry: Geometry,
    role: Role,
    listener: TcpListener,
    backend: SocketAddr,
    events: mpsc::Sender<Event>,
    start: oneshot::Receiver<()>,
    warmup: oneshot::Receiver<()>,
    tail: oneshot::Receiver<bool>,
}

impl Gate {
    async fn run(self) {
        let Self {
            geometry,
            role,
            listener,
            backend,
            events,
            start,
            warmup,
            tail,
        } = self;
        let (client, _) = listener.accept().await.unwrap();
        let connection = async move {
            let (mut writer, mut incoming, forward) = relay_to_seed(client, backend).await;
            start.await.unwrap();
            let mut warmup = Some(warmup);
            let mut tail = Some(tail);
            while let Some(frame) = incoming.next().await {
                let frame = frame.unwrap();
                if let Some((start, _)) = payload_range(&frame) {
                    if let Some(release) = warmup.take() {
                        assert_eq!(
                            start,
                            match role {
                                Role::Original => geometry.prefix,
                                Role::Replacement => geometry.replacement_start,
                            }
                        );
                        events.send(Event::Warmup(role)).await.unwrap();
                        release.await.unwrap();
                    }
                    if start == geometry.tail {
                        events.send(Event::Tail(role)).await.unwrap();
                        if !tail
                            .take()
                            .expect("one final range per peer")
                            .await
                            .unwrap()
                        {
                            // A valid frame's header and a prefix of its body arrive;
                            // the remainder stays withheld until Core closes the peer.
                            writer.write_all(&frame[..33]).await.unwrap();
                            events.send(Event::Truncated(role)).await.unwrap();
                            assert_peer_closed(forward).await;
                            return;
                        }
                    }
                }
                writer.write_all(&frame).await.unwrap();
            }
            assert_peer_closed(forward).await;
        };
        tokio::select! {
            () = connection => {},
            unexpected = listener.accept() => panic!("endgame peer reconnected instead of retaining its connection: {unexpected:?}"),
        }
    }
}

async fn download_peer(
    options: emulebb_ed2k::ed2k_tcp::Ed2kPeerDownloadOptions<'_>,
) -> Result<Ed2kPeerDownloadReport> {
    emulebb_ed2k::ed2k_tcp::download_files_from_peer(options, Vec::new()).await
}

#[tokio::test]
async fn original_endgame_copy_wins_and_drains_replacement_peer() {
    tokio::time::timeout(
        Duration::from_secs(50),
        qualify(Role::Original, Geometry::COMPLETE),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn replacement_endgame_copy_wins_and_drains_original_peer() {
    tokio::time::timeout(
        Duration::from_secs(50),
        qualify(Role::Replacement, Geometry::COMPLETE),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn nonterminal_verified_part_drains_redundant_endgame_peer() {
    tokio::time::timeout(
        Duration::from_secs(120),
        qualify(Role::Replacement, Geometry::PARTIAL),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn nonterminal_original_copy_drains_replacement_endgame_peer() {
    tokio::time::timeout(
        Duration::from_secs(120),
        qualify(Role::Original, Geometry::PARTIAL),
    )
    .await
    .unwrap();
}

async fn qualify(winner: Role, geometry: Geometry) {
    // WHY: these loopback failures cross spawned seed/receiver tasks. A test-only
    // subscriber preserves their close reasons in libtest's captured output;
    // production tracing setup and transfer timing remain unchanged.
    static TRACING: std::sync::Once = std::sync::Once::new();
    TRACING.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("emulebb_ed2k::ed2k_tcp::listener=debug,emulebb_ed2k::ed2k_tcp::download::session=debug")
            .without_time()
            .with_ansi(false)
            .with_test_writer()
            .try_init();
    });
    let Geometry {
        size,
        prefix,
        served,
        ..
    } = geometry;
    eprintln!("endgame setup: size={size}, served={served}");
    let root = unique_runtime_dir(match winner {
        Role::Original => "endgame-original",
        Role::Replacement => "endgame-replacement",
    });
    // Deterministic, incompressible test bytes using the already pinned digest.
    let mut payload = Vec::with_capacity(size + 16);
    for index in 0..size.div_ceil(16) {
        payload.extend_from_slice(&Md4::digest((index as u64).to_le_bytes()));
    }
    payload.truncate(size);
    let hashset: Vec<[u8; 16]> = payload
        .chunks(emulebb_ed2k::ed2k_transfer::ED2K_PART_SIZE as usize)
        .map(|part| Md4::digest(part).into())
        .collect();
    let hash = Ed2kHash::from_bytes(if hashset.len() == 1 {
        hashset[0]
    } else {
        Md4::digest(hashset.concat()).into()
    });
    let library = root.join("library");
    std::fs::create_dir_all(&library).unwrap();
    std::fs::write(library.join("endgame.bin"), &payload).unwrap();
    let mut seeds = Vec::new();
    let mut backends = Vec::new();
    for id in 0..2u8 {
        let (seed, network) = super::download_preparation::local_preparation_core(
            &root.join(format!("seed-{id}")),
            [0x91 + id; 16],
            None,
        );
        if served < size {
            // Real stopped partial sources advertise only their verified first part.
            let token = admit_scheduler_test_job(
                &seed.ed2k_transfers,
                &root.join(format!("seed-{id}")),
                hash,
                "endgame.bin".into(),
                size as u64,
            )
            .await;
            drop(
                seed.ed2k_transfers
                    .store_md4_hashset(token, hashset.clone())
                    .await
                    .unwrap(),
            );
            seed.ed2k_transfers
                .store_piece_data(token, 0, &payload[..served])
                .await
                .unwrap();
            assert!(seed.ed2k_transfers.stop_download_job(token).await.unwrap());
        } else {
            seed.create_library_root(&library.to_string_lossy(), false)
                .await
                .unwrap()
                .unwrap();
            let shares = seed.reload_shared_directories().await.unwrap();
            assert!(shares.iter().any(|entry| entry.hash == hash.to_string()));
            drop(shares);
        }
        seed.connect_ed2k().await.unwrap();
        // Isolate endgame ownership from the independent upload rotation policy:
        // the nonterminal fixture's resumable prefix exceeds the normal 90% cap.
        let mut upload_policy = network.ed2k.upload_queue.clone();
        upload_policy.session_transfer_percent = 0;
        seed.ed2k_transfers
            .apply_upload_queue_policy(&upload_policy)
            .await;
        backends.push(SocketAddr::from((Ipv4Addr::LOCALHOST, network.listen_port)));
        seeds.push(seed);
    }
    eprintln!("endgame seeds ready");
    let storage = root.join("receiver");
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&storage).unwrap());
    let token =
        admit_scheduler_test_job(&runtime, &storage, hash, "endgame.bin".into(), size as u64).await;
    let ident =
        Arc::new(Ed2kSecureIdent::load_or_create(&root.join("receiver-ident.der")).unwrap());
    let prefix_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let prefix_source = direct_test_source(
        hash,
        Ipv4Addr::LOCALHOST,
        prefix_listener.local_addr().unwrap().port(),
    );
    let prefix_server = tokio::spawn(prefix_relay(prefix_listener, backends[0], prefix));
    let mut hello_identity = direct_download_options(
        token,
        Arc::clone(&runtime),
        Arc::clone(&ident),
        hash.to_string(),
        "endgame.bin".into(),
        size as u64,
        Vec::new(),
    )
    .hello_identity;
    hello_identity.client_id = 0x5912_0559;
    let report = tokio::time::timeout(
        Duration::from_secs(60),
        download_peer(Ed2kPeerDownloadOptions {
            job_token: token,
            bind_ip: Ipv4Addr::LOCALHOST,
            egress_route: emulebb_ed2k::networking::EgressRoute::default(),
            peer: &prefix_source,
            hello_identity,
            secure_ident: &ident,
            transfer_runtime: &runtime,
            display_name: "endgame.bin".into(),
            file_size: size as u64,
            current_source_count: 0,
            timeout: Duration::from_secs(30),
            upload_context: None,
            established_context: None,
            reask_register: None,
        }),
    )
    .await
    .expect("prefix download must finish")
    .unwrap();
    assert_eq!(
        report.file_outcomes[0].outcome,
        Ed2kPeerDownloadOutcome::AcceptedButIncomplete
    );
    prefix_server.await.unwrap_or_else(|error| {
        panic!("prefix relay failed ({error}); downloader report: {report:?}")
    });
    eprintln!("endgame prefix received");
    runtime.checkpoint_dirty_download_progress().await.unwrap();
    assert_eq!(
        runtime
            .download_job(token.job_id)
            .await
            .unwrap()
            .unwrap()
            .checkpointed_bytes,
        prefix as u64
    );
    let baseline = runtime.download_resource_snapshot();
    let bytes_before = runtime.session_downloaded_bytes();
    let (events, mut received) = mpsc::channel(8);
    let mut gates = Vec::new();
    let mut sources = Vec::new();
    let mut controls = Vec::new();
    for (id, role) in [Role::Original, Role::Replacement].into_iter().enumerate() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        sources.push(direct_test_source(
            hash,
            Ipv4Addr::LOCALHOST,
            listener.local_addr().unwrap().port(),
        ));
        let (start_tx, start) = oneshot::channel();
        let (warmup_tx, warmup) = oneshot::channel();
        let (tail_tx, tail) = oneshot::channel();
        controls.push((Some(start_tx), Some(warmup_tx), Some(tail_tx)));
        gates.push(tokio::spawn(
            Gate {
                geometry,
                role,
                listener,
                backend: backends[id],
                events: events.clone(),
                start,
                warmup,
                tail,
            }
            .run(),
        ));
    }
    let mut options = direct_download_options(
        token,
        Arc::clone(&runtime),
        ident,
        hash.to_string(),
        "endgame.bin".into(),
        size as u64,
        sources,
    );
    options.bind_ip = Ipv4Addr::LOCALHOST;
    options.hello_identity = hello_identity;
    options.max_parallel_download_peers = 2;
    options.connect_timeout = Duration::from_secs(40);
    let operation = tokio::spawn(run_ed2k_direct_downloads(
        options,
        |bind_ip,
         source,
         hello_identity,
         secure_ident,
         runtime,
         job_token,
         display_name,
         file_size,
         timeout| async move {
            download_peer(Ed2kPeerDownloadOptions {
                job_token,
                bind_ip,
                egress_route: emulebb_ed2k::networking::EgressRoute::default(),
                peer: &source,
                hello_identity,
                secure_ident: &secure_ident,
                transfer_runtime: &runtime,
                display_name,
                file_size,
                current_source_count: 0,
                timeout,
                upload_context: None,
                established_context: None,
                reask_register: None,
            })
            .await
        },
    ));
    controls[0].0.take().unwrap().send(()).unwrap();
    expect_event(&mut received, Event::Warmup(Role::Original)).await;
    controls[1].0.take().unwrap().send(()).unwrap();
    expect_event(&mut received, Event::Warmup(Role::Replacement)).await;
    // Give the original a small, measured nonzero rate with generous fivefold
    // takeover margin, independent of startup speed or CPU contention.
    tokio::time::sleep(Duration::from_secs(2)).await;
    controls[0].1.take().unwrap().send(()).unwrap();
    expect_event(&mut received, Event::Tail(Role::Original)).await;
    // Native lease aging uses std::time::Instant; exercise its real 15s bound.
    tokio::time::sleep(Duration::from_secs(16)).await;
    controls[1].1.take().unwrap().send(()).unwrap();
    expect_event(&mut received, Event::Tail(Role::Replacement)).await;
    let winner_id = usize::from(winner == Role::Replacement);
    let loser_id = 1 - winner_id;
    let loser = if loser_id == 0 {
        Role::Original
    } else {
        Role::Replacement
    };
    controls[loser_id].2.take().unwrap().send(false).unwrap();
    expect_event(&mut received, Event::Truncated(loser)).await;
    tokio::task::yield_now().await;
    controls[winner_id].2.take().unwrap().send(true).unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(8), operation).await;
    if outcome.is_err() {
        let manifest = runtime.manifest(token).await.unwrap();
        eprintln!(
            "endgame drain timed out: completed={}, first part={:?}",
            manifest.completed, manifest.pieces[0].state
        );
    }
    let outcome = outcome
        .expect("verified payload must retire redundant peer before socket timeout")
        .unwrap()
        .unwrap();
    assert_eq!(outcome.completed, served == size);
    for gate in gates {
        tokio::time::timeout(Duration::from_secs(5), gate)
            .await
            .unwrap()
            .unwrap();
    }
    let manifest = runtime.manifest(token).await.unwrap();
    assert_eq!(manifest.completed, served == size);
    if served < size {
        assert_eq!(
            manifest.pieces[0].state,
            emulebb_ed2k::ed2k_transfer::Ed2kTransferState::Verified
        );
        assert_ne!(
            manifest.pieces[1].state,
            emulebb_ed2k::ed2k_transfer::Ed2kTransferState::Verified
        );
    }
    let mut actual = Vec::with_capacity(served);
    for start in (0..served).step_by(BLOCK) {
        actual.extend(
            runtime
                .read_verified_range(&hash, start as u64, (start + BLOCK).min(served) as u64)
                .await
                .unwrap()
                .unwrap(),
        );
    }
    assert_eq!(actual, payload[..served]);
    assert_eq!(
        runtime.session_downloaded_bytes() - bytes_before,
        (served - prefix) as u64
    );
    assert!(runtime.requested_download_parts(token).is_empty());
    let after = runtime.download_resource_snapshot();
    assert_eq!(after.connections, baseline.connections);
    assert_eq!(after.transient_bytes, baseline.transient_bytes);
    for seed in seeds {
        seed.disconnect_ed2k().await.unwrap();
    }
}
