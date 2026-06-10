use super::*;

fn with_obfuscation(mut identity: Ed2kHelloIdentity) -> Ed2kHelloIdentity {
    identity.connect_options = emule_connect_options(true);
    identity
}

#[tokio::test]
async fn listener_upload_queue_promotes_waiter_after_disconnect() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-queue-disconnect",
        listener_test_identity(0x22, 0x1234_5678, 41001, 41000),
        [0x3D; 16],
        0x1122_3344,
    )
    .await;
    runtime.use_one_slot_upload_queue().await;
    let file = runtime
        .seed_verified_upload_file("queued.txt", vec![0x51; 4096])
        .await;
    let server = runtime.spawn_listener_connections(2);

    let first_stream = connect_peer_until_upload_accepted(
        runtime.peer_addr,
        listener_test_identity(0x31, 0x0102_0304, 4661, 4665),
        &file.file_hash,
    )
    .await;
    let mut second_stream = connect_peer_until_queue_rank(
        runtime.peer_addr,
        listener_test_identity(0x32, 0x0506_0708, 4662, 4666),
        &file.file_hash,
        1,
    )
    .await;

    drop(first_stream);

    wait_for_upload_accept_timeout(&mut second_stream).await;
    drop(second_stream);
    server.await.unwrap();
}

#[tokio::test]
async fn listener_upload_queue_promotes_waiter_after_cancel_transfer() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-queue-cancel",
        listener_test_identity(0x23, 0x2233_4455, 41002, 41003),
        [0x3E; 16],
        0x5566_7788,
    )
    .await;
    runtime.use_one_slot_upload_queue().await;
    let file = runtime
        .seed_verified_upload_file("queued.txt", vec![0x61; 4096])
        .await;
    let server = runtime.spawn_listener_connections(2);

    let mut first_stream = connect_peer_until_upload_accepted(
        runtime.peer_addr,
        listener_test_identity(0x41, 0x1111_1111, 4661, 4665),
        &file.file_hash,
    )
    .await;
    let mut second_stream = connect_peer_until_queue_rank(
        runtime.peer_addr,
        listener_test_identity(0x42, 0x2222_2222, 4662, 4666),
        &file.file_hash,
        1,
    )
    .await;

    send_cancel_transfer(&mut first_stream).await;
    drop(first_stream);

    wait_for_upload_accept_timeout(&mut second_stream).await;
    drop(second_stream);
    server.await.unwrap();
}

#[tokio::test]
async fn listener_upload_queue_obfuscated_waiter_promotes_after_cancel_transfer() {
    let listener_identity =
        with_obfuscation(listener_test_identity(0x2A, 0x3141_2718, 41002, 41003));
    let listener_user_hash = listener_identity.user_hash;
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-queue-obfuscated-cancel",
        listener_identity,
        [0x4A; 16],
        0x1234_8765,
    )
    .await;
    runtime.use_one_slot_upload_queue().await;
    let file = runtime
        .seed_verified_upload_file("queued-obfuscated.txt", vec![0x62; 4096])
        .await;
    let server = runtime.spawn_listener_connections(2);

    let mut first_transport = connect_obfuscated_peer_until_upload_accepted(
        runtime.peer_addr,
        listener_user_hash,
        with_obfuscation(listener_test_identity(0x43, 0x1111_3333, 4661, 4665)),
        &file.file_hash,
    )
    .await;
    let mut second_transport = connect_obfuscated_peer_until_queue_rank(
        runtime.peer_addr,
        listener_user_hash,
        with_obfuscation(listener_test_identity(0x44, 0x2222_4444, 4662, 4666)),
        &file.file_hash,
        1,
    )
    .await;

    send_transport_cancel_transfer(&mut first_transport).await;

    wait_for_transport_upload_accept_timeout(&mut second_transport).await;
    drop(second_transport);
    server.await.unwrap();
}

#[tokio::test]
async fn listener_upload_queue_refreshes_waiting_rank_before_promotion() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-queue-refresh",
        listener_test_identity(0x51, 0x3141_5926, 41002, 41003),
        [0x4E; 16],
        0x2233_4455,
    )
    .await;
    runtime.use_one_slot_upload_queue().await;
    let file = runtime
        .seed_verified_upload_file("queued.txt", vec![0x71; 4096])
        .await;
    let server = runtime.spawn_listener_connections(2);

    let mut first_stream = connect_peer_until_upload_accepted(
        runtime.peer_addr,
        listener_test_identity(0x61, 0x1111_2222, 4661, 4665),
        &file.file_hash,
    )
    .await;
    let mut second_stream = connect_peer_until_queue_rank(
        runtime.peer_addr,
        listener_test_identity(0x62, 0x2222_3333, 4662, 4666),
        &file.file_hash,
        1,
    )
    .await;

    wait_for_queue_rank_timeout(&mut second_stream, 1).await;

    send_cancel_transfer(&mut first_stream).await;
    drop(first_stream);

    wait_for_upload_accept_timeout(&mut second_stream).await;
    drop(second_stream);
    server.await.unwrap();
}

#[tokio::test]
async fn listener_upload_queue_reconnects_waiter_by_hello_identity() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-queue-reconnect-hello",
        listener_test_identity(0x71, 0x4242_2424, 41002, 41003),
        [0x5E; 16],
        0x6677_8899,
    )
    .await;
    runtime.use_one_slot_upload_queue().await;
    let file = runtime
        .seed_verified_upload_file("queued.txt", vec![0x7B; 4096])
        .await;
    let server = runtime.spawn_listener_loop();

    let mut first_stream = connect_peer_until_upload_accepted(
        runtime.peer_addr,
        listener_test_identity(0x81, 0x1111_1111, 4661, 4665),
        &file.file_hash,
    )
    .await;

    let queued_identity = listener_test_identity(0x91, 0x3333_3333, 4662, 4666);
    let queued_stream =
        connect_peer_until_queue_rank(runtime.peer_addr, queued_identity, &file.file_hash, 1).await;
    drop(queued_stream);

    let mut reconnected_stream =
        connect_peer_until_queue_rank(runtime.peer_addr, queued_identity, &file.file_hash, 1).await;

    send_cancel_transfer(&mut first_stream).await;
    drop(first_stream);

    wait_for_upload_accept_timeout(&mut reconnected_stream).await;
    drop(reconnected_stream);
    server.abort();
}

#[tokio::test]
async fn listener_upload_queue_preserves_waiter_rank_across_file_switch() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-queue-file-switch",
        listener_test_identity(0x71, 0x4343_2525, 41002, 41003),
        [0x6E; 16],
        0x7788_99AA,
    )
    .await;
    runtime.use_one_slot_upload_queue().await;
    let first_file = runtime
        .seed_verified_upload_file("queued-one.txt", vec![0x7B; 4096])
        .await;
    let second_file = runtime
        .seed_verified_upload_file("queued-two.txt", vec![0x8C; 4096])
        .await;
    let server = runtime.spawn_listener_loop();

    let mut first_stream = connect_peer_until_upload_accepted(
        runtime.peer_addr,
        listener_test_identity(0x81, 0x1111_1111, 4661, 4665),
        &first_file.file_hash,
    )
    .await;
    let mut queued_stream = connect_peer_until_queue_rank(
        runtime.peer_addr,
        listener_test_identity(0x91, 0x3333_3333, 4662, 4666),
        &first_file.file_hash,
        1,
    )
    .await;
    let mut trailing_stream = connect_peer_until_queue_rank(
        runtime.peer_addr,
        listener_test_identity(0xA1, 0x4444_4444, 4663, 4667),
        &first_file.file_hash,
        2,
    )
    .await;

    request_upload_file(&mut queued_stream, &second_file.file_hash).await;
    wait_for_queue_rank(&mut queued_stream, 1).await;
    wait_for_queue_rank_timeout(&mut trailing_stream, 2).await;

    send_cancel_transfer(&mut first_stream).await;
    drop(first_stream);

    wait_for_upload_accept_timeout(&mut queued_stream).await;

    drop(queued_stream);
    drop(trailing_stream);
    server.abort();
}
