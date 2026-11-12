//! Bounded, synthetic loopback HTTP replies for discovery import tests.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

pub struct Reply {
    pub parts: Vec<Vec<u8>>,
    pub before: Duration,
    pub between: Duration,
}

impl Reply {
    pub fn raw(bytes: &[u8]) -> Self {
        Self {
            parts: vec![bytes.to_vec()],
            before: Duration::ZERO,
            between: Duration::ZERO,
        }
    }

    pub fn body(bytes: &[u8]) -> Self {
        Self::raw(
            &[
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                )
                .as_bytes(),
                bytes,
            ]
            .concat(),
        )
    }

    pub fn redirect(url: &str) -> Self {
        Self::raw(format!("HTTP/1.1 302 Found\r\nLocation: {url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes())
    }
}

pub struct Server {
    pub url: String,
    pub hits: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn server(replies: Vec<Reply>) -> Server {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = hits.clone();
    let task = tokio::spawn(async move {
        for reply in replies {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            seen.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(reply.before).await;
            for part in reply.parts {
                if stream.write_all(&part).await.is_err() {
                    break;
                }
                tokio::time::sleep(reply.between).await;
            }
        }
    });
    Server { url, hits, task }
}
