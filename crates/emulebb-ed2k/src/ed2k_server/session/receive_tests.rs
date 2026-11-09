//! Cancellation at a publication tick must not lose bytes or advance RC4 twice.

use std::{
    future::{Future, poll_fn},
    io,
    task::Poll,
    time::Duration,
};

use tokio::io::AsyncWriteExt;

use super::super::{OP_FOUNDSOURCES, OP_SEARCHRESULT};
use super::{Rc4KeyStream, ServerSession, TCP_PACKET_HEADER_LEN, encode_packet};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn publication_tick_preserves_a_plain_partial_header() {
    assert_frame_survives_ticks(false, &[2]).await;
}

#[tokio::test]
async fn publication_tick_preserves_a_plain_partial_payload() {
    assert_frame_survives_ticks(false, &[TCP_PACKET_HEADER_LEN + 2]).await;
}

#[tokio::test]
async fn publication_tick_preserves_an_obfuscated_partial_header() {
    assert_frame_survives_ticks(true, &[2]).await;
}

#[tokio::test]
async fn publication_tick_preserves_an_obfuscated_partial_payload() {
    assert_frame_survives_ticks(true, &[TCP_PACKET_HEADER_LEN + 2]).await;
}

#[tokio::test]
async fn repeated_publication_ticks_preserve_a_plain_frame_and_its_successor() {
    assert_frame_survives_ticks(
        false,
        &[2, TCP_PACKET_HEADER_LEN + 1, TCP_PACKET_HEADER_LEN + 3],
    )
    .await;
}

#[tokio::test]
async fn repeated_publication_ticks_preserve_an_obfuscated_frame_and_its_successor() {
    assert_frame_survives_ticks(
        true,
        &[2, TCP_PACKET_HEADER_LEN + 1, TCP_PACKET_HEADER_LEN + 3],
    )
    .await;
}

async fn assert_frame_survives_ticks(obfuscated: bool, cuts: &[usize]) {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let (mut session, mut peer) = super::tests::connected_test_session_with_peer().await;
        let first_payload = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16];
        let second_payload = [0x21, 0x22, 0x23];
        let mut wire = encode_packet(OP_SEARCHRESULT, &first_payload, false).unwrap();
        wire.extend_from_slice(&encode_packet(OP_FOUNDSOURCES, &second_payload, false).unwrap());
        if obfuscated {
            let key = [0x53; 16];
            let mut peer_cipher = Rc4KeyStream::new_without_discard(&key);
            peer_cipher.apply(&mut wire);
            session.receive_cipher = Some(Rc4KeyStream::new_without_discard(&key));
        }

        let mut sent = 0;
        for &cut in cuts {
            let prefix = &wire[sent..cut];
            peer.write_all(prefix).await.unwrap();
            // Wait without consuming the bytes so the next poll must see the
            // complete prefix, independently of loopback scheduling or TCP splits.
            let mut visible = vec![0; prefix.len()];
            loop {
                if session.stream.peek(&mut visible).await.unwrap() == prefix.len() {
                    assert_eq!(visible, prefix);
                    break;
                }
                tokio::task::yield_now().await;
            }

            cancel_read_at_pending(&mut session).await;
            // WHY: a regression must not pass because its prefix remained wholly
            // in the kernel while the read future was cancelled before any I/O.
            let mut unexpected = [0; 1];
            assert!(matches!(
                session.stream.try_read(&mut unexpected),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock
            ));
            sent = cut;
        }
        peer.write_all(&wire[sent..]).await.unwrap();

        let first = session.read_packet().await.unwrap().unwrap();
        assert_eq!(first.opcode, OP_SEARCHRESULT);
        assert_eq!(first.payload, first_payload);
        let second = session.read_packet().await.unwrap().unwrap();
        assert_eq!(second.opcode, OP_FOUNDSOURCES);
        assert_eq!(second.payload, second_payload);
        drop(peer);
        assert!(session.read_packet().await.unwrap().is_none());
    })
    .await
    .expect("cancelled server frame must resume and decode its successor");
}

async fn cancel_read_at_pending(session: &mut ServerSession) {
    let mut reading = std::pin::pin!(session.read_packet());
    poll_fn(|context| match reading.as_mut().poll(context) {
        // Dropping a polled, pending read has the same cancellation semantics
        // as the publication timer winning the driver's select! branch.
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(result) => {
            panic!("read completed before the cancellation boundary: {result:?}")
        }
    })
    .await;
}
