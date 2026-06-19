use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

const SOURCE_EXCHANGE_REASK_INTERVAL: Duration = Duration::from_secs(40 * 60);
const SOURCE_EXCHANGE_COMMON_REASK_INTERVAL: Duration = Duration::from_secs(160 * 60);
const SOURCE_EXCHANGE_FILE_ANSWER_INTERVAL: Duration = Duration::from_secs(5 * 60);
const SOURCE_EXCHANGE_COMMON_FILE_ANSWER_INTERVAL: Duration = Duration::from_secs(20 * 60);
const SOURCE_EXCHANGE_RARE_FILE: usize = 50;
const SOURCE_EXCHANGE_VERY_RARE_FILE: usize = SOURCE_EXCHANGE_RARE_FILE / 5;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SourceExchangeRequestKey {
    file_hash: String,
    peer_addr: SocketAddr,
    user_hash: Option<[u8; 16]>,
}

#[derive(Debug, Default)]
pub(super) struct SourceExchangeState {
    requests: Arc<Mutex<HashMap<SourceExchangeRequestKey, Instant>>>,
    file_answers: Arc<Mutex<HashMap<String, Instant>>>,
}

impl SourceExchangeState {
    pub(super) async fn should_request(
        &self,
        file_hash: &str,
        peer_addr: SocketAddr,
        user_hash: Option<[u8; 16]>,
        current_source_count: usize,
        now: Instant,
    ) -> bool {
        let file_answer_interval = file_answer_interval(current_source_count);
        if !file_answer_interval.is_zero() {
            let answers = self.file_answers.lock().await;
            if answers.get(file_hash).is_some_and(|last_answered| {
                now.duration_since(*last_answered) <= file_answer_interval
            }) {
                return false;
            }
        }

        let reask_interval = reask_interval(current_source_count);
        let key = SourceExchangeRequestKey {
            file_hash: file_hash.to_string(),
            peer_addr,
            user_hash,
        };
        let mut requests = self.requests.lock().await;
        let allowed = requests
            .get(&key)
            .is_none_or(|last_requested| now.duration_since(*last_requested) > reask_interval);
        if allowed {
            requests.insert(key, now);
        }
        allowed
    }

    pub(super) async fn note_answer(&self, file_hash: &str, now: Instant) {
        self.file_answers
            .lock()
            .await
            .insert(file_hash.to_string(), now);
    }
}

fn reask_interval(current_source_count: usize) -> Duration {
    if current_source_count > SOURCE_EXCHANGE_RARE_FILE {
        SOURCE_EXCHANGE_COMMON_REASK_INTERVAL
    } else {
        SOURCE_EXCHANGE_REASK_INTERVAL
    }
}

fn file_answer_interval(current_source_count: usize) -> Duration {
    if current_source_count <= SOURCE_EXCHANGE_VERY_RARE_FILE {
        Duration::ZERO
    } else if current_source_count <= SOURCE_EXCHANGE_RARE_FILE {
        SOURCE_EXCHANGE_FILE_ANSWER_INTERVAL
    } else {
        SOURCE_EXCHANGE_COMMON_FILE_ANSWER_INTERVAL
    }
}
