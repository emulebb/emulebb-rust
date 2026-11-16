use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use emulebb_metadata::JobToken;
use std::sync::Mutex;

const SOURCE_EXCHANGE_REASK_INTERVAL: Duration = Duration::from_secs(40 * 60);
const SOURCE_EXCHANGE_COMMON_REASK_INTERVAL: Duration = Duration::from_secs(160 * 60);
const SOURCE_EXCHANGE_FILE_ANSWER_INTERVAL: Duration = Duration::from_secs(5 * 60);
const SOURCE_EXCHANGE_COMMON_FILE_ANSWER_INTERVAL: Duration = Duration::from_secs(20 * 60);
const SOURCE_EXCHANGE_RARE_FILE: usize = 50;
const SOURCE_EXCHANGE_VERY_RARE_FILE: usize = SOURCE_EXCHANGE_RARE_FILE / 5;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SourceExchangeRequestKey {
    peer_addr: SocketAddr,
    user_hash: Option<[u8; 16]>,
}

#[derive(Debug, Default, Clone)]
pub(super) struct SourceExchangeState {
    requests: Arc<Mutex<HashMap<JobToken, HashMap<SourceExchangeRequestKey, Instant>>>>,
    file_answers: Arc<Mutex<HashMap<JobToken, Instant>>>,
}

impl SourceExchangeState {
    pub(super) fn should_request(
        &self,
        token: JobToken,
        peer_addr: SocketAddr,
        user_hash: Option<[u8; 16]>,
        current_source_count: usize,
        now: Instant,
    ) -> bool {
        let file_answer_interval = file_answer_interval(current_source_count);
        if !file_answer_interval.is_zero() {
            let answers = self.file_answers.lock().unwrap();
            if answers.get(&token).is_some_and(|last_answered| {
                now.duration_since(*last_answered) <= file_answer_interval
            }) {
                return false;
            }
        }

        let reask_interval = reask_interval(current_source_count);
        let key = SourceExchangeRequestKey {
            peer_addr,
            user_hash,
        };
        let mut jobs = self.requests.lock().unwrap();
        let requests = jobs.entry(token).or_default();
        let allowed = requests
            .get(&key)
            .is_none_or(|last_requested| now.duration_since(*last_requested) > reask_interval);
        if allowed {
            requests.insert(key, now);
        }
        allowed
    }

    pub(super) fn clear(&self, token: JobToken) {
        self.requests.lock().unwrap().remove(&token);
        self.file_answers.lock().unwrap().remove(&token);
    }

    pub(super) fn note_answer(&self, token: JobToken, now: Instant) {
        self.file_answers.lock().unwrap().insert(token, now);
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
