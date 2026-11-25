//! One outstanding browse per established peer. The wire has no request identifier.
use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use tokio::sync::watch;

use crate::{
    ed2k_string::Ed2kStringEncoding,
    ed2k_tcp::{
        OP_ASKSHAREDDENIEDANS, OP_ASKSHAREDDIRS, OP_ASKSHAREDDIRSANS, OP_ASKSHAREDFILES,
        OP_ASKSHAREDFILESANSWER, OP_ASKSHAREDFILESDIRANS, OP_EDONKEYPROT,
        codec::{
            encode_packet,
            shared_browse::{
                PeerBrowseFile, decode_browse_dirs, decode_browse_files, encode_browse_dir_request,
                split_browse_directory,
            },
        },
    },
};

const MAX_FILES: usize = 100_000;
const MAX_DIRS: usize = 100_000;
const MAX_SESSIONS: usize = 4096;
const MAX_SEARCHES: usize = 128;
const MAX_PAGE: usize = 512;
const RETAINED_BYTES: usize = 64 * 1024 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const RETENTION: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerBrowseStatus {
    Pending,
    Complete,
    Denied,
    Timeout,
    Disconnected,
    Malformed,
    Limit,
}

#[derive(Debug, Clone)]
pub struct PeerBrowseStart {
    pub search_id: u64,
    pub already_pending: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerBrowseResult {
    pub directory: Option<Arc<str>>,
    pub file: PeerBrowseFile,
}

#[derive(Debug, Clone)]
pub struct PeerBrowsePage {
    pub search_id: u64,
    pub status: PeerBrowseStatus,
    pub total: usize,
    pub offset: usize,
    pub files: Vec<PeerBrowseResult>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Peer {
    hash: [u8; 16],
    endpoint: SocketAddr,
}

impl Peer {
    fn matches(self, hash: Option<[u8; 16]>, endpoint: SocketAddr) -> bool {
        self.endpoint == endpoint && hash.is_none_or(|hash| hash == self.hash)
    }
}

struct Connection {
    peer: Peer,
    commands: watch::Sender<Option<u64>>,
    allows: bool,
    dirs: bool,
    strings: Ed2kStringEncoding,
    pending: Option<u64>,
    // Late replies from an abandoned request cannot be distinguished on this connection.
    abandoned: bool,
}

enum Phase {
    Queued,
    Flat,
    Directories,
    Files(VecDeque<Vec<u8>>),
    Finished,
}

struct Record {
    connection: u64,
    peer: Peer,
    phase: Phase,
    status: PeerBrowseStatus,
    touched: Instant,
    strings: Ed2kStringEncoding,
    chunks: VecDeque<Box<[PeerBrowseResult]>>,
    total: usize,
    bytes: usize,
    revision: u64,
}

#[derive(Default)]
struct RegistryState {
    next: u64,
    connections: BTreeMap<u64, Connection>,
    searches: BTreeMap<u64, Record>,
}

impl RegistryState {
    fn next_id(&mut self) -> Option<u64> {
        self.next = self.next.checked_add(1)?;
        Some(self.next)
    }

    fn finish(&mut self, id: u64, status: PeerBrowseStatus, now: Instant) {
        let Some(record) = self.searches.get_mut(&id) else {
            return;
        };
        if record.status != PeerBrowseStatus::Pending {
            return;
        }
        let on_wire = !matches!(record.phase, Phase::Queued);
        record.status = status;
        record.phase = Phase::Finished;
        record.touched = now;
        if let Some(conn) = self.connections.get_mut(&record.connection) {
            conn.pending = None;
            conn.abandoned |= on_wire
                && matches!(
                    status,
                    PeerBrowseStatus::Timeout
                        | PeerBrowseStatus::Malformed
                        | PeerBrowseStatus::Limit
                );
        }
    }

    fn expire(&mut self, now: Instant) {
        let expired: Vec<_> = self
            .searches
            .iter()
            .filter_map(|(&id, r)| {
                (r.status == PeerBrowseStatus::Pending
                    && now.duration_since(r.touched) >= IDLE_TIMEOUT)
                    .then_some(id)
            })
            .collect();
        for id in expired {
            self.finish(id, PeerBrowseStatus::Timeout, now);
        }
        self.searches.retain(|_, r| {
            r.status == PeerBrowseStatus::Pending || now.duration_since(r.touched) < RETENTION
        });
    }

    fn connection_for(&self, hash: Option<[u8; 16]>, endpoint: SocketAddr) -> Option<u64> {
        let mut matches = self
            .connections
            .iter()
            .rev()
            .filter(|(_, conn)| conn.peer.matches(hash, endpoint));
        let (&first, conn) = matches.next()?;
        let mut best = (first, conn);
        for (&id, other) in matches {
            if other.peer.hash != conn.peer.hash {
                return None;
            }
            let score = |c: &Connection| (c.pending.is_some(), c.allows && !c.abandoned);
            if score(other) > score(best.1) {
                best = (id, other);
            }
        }
        Some(best.0)
    }

    fn evict_finished(&mut self) -> bool {
        let oldest = self
            .searches
            .iter()
            .filter(|(_, r)| r.status != PeerBrowseStatus::Pending)
            .min_by_key(|(_, r)| r.touched)
            .map(|(&id, _)| id);
        oldest.is_some_and(|id| self.searches.remove(&id).is_some())
    }

    fn reserve_bytes(&mut self, id: u64, charge: usize) -> bool {
        while self
            .searches
            .values()
            .map(|r| r.bytes)
            .sum::<usize>()
            .saturating_add(charge)
            > RETAINED_BYTES
        {
            if !self.evict_finished() {
                return false;
            }
        }
        self.searches.get_mut(&id).expect("pending browse").bytes += charge;
        true
    }

    fn page(&self, id: u64, offset: usize, limit: usize) -> Option<PeerBrowsePage> {
        let r = self.searches.get(&id)?;
        let offset = offset.min(r.total);
        let limit = limit.min(MAX_PAGE);
        let mut skip = offset;
        let mut files = Vec::with_capacity(limit.min(r.total - offset));
        for chunk in &r.chunks {
            if files.len() == limit {
                break;
            }
            if skip >= chunk.len() {
                skip -= chunk.len();
                continue;
            }
            files.extend(chunk[skip..].iter().take(limit - files.len()).cloned());
            skip = 0;
        }
        Some(PeerBrowsePage {
            search_id: id,
            status: r.status,
            total: r.total,
            offset,
            files,
        })
    }
}

#[derive(Default, Clone)]
pub struct PeerBrowseRegistry {
    state: Arc<Mutex<RegistryState>>,
}

impl std::fmt::Debug for PeerBrowseRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Browsed filenames and directory labels do not belong in runtime debug output.
        f.debug_struct("PeerBrowseRegistry").finish_non_exhaustive()
    }
}

impl PeerBrowseRegistry {
    pub(crate) fn register(
        &self,
        user_hash: [u8; 16],
        endpoint: SocketAddr,
        allows_browse: bool,
        supports_dirs: bool,
        strings: Ed2kStringEncoding,
    ) -> Option<PeerBrowseSession> {
        let mut state = self.state.lock().ok()?;
        if state.connections.len() >= MAX_SESSIONS {
            return None;
        }
        let id = state.next_id()?;
        let (tx, rx) = watch::channel(None);
        state.connections.insert(
            id,
            Connection {
                peer: Peer {
                    hash: user_hash,
                    endpoint,
                },
                commands: tx,
                allows: allows_browse,
                dirs: supports_dirs,
                strings,
                pending: None,
                abandoned: false,
            },
        );
        Some(PeerBrowseSession {
            registry: self.clone(),
            id,
            rx,
        })
    }

    pub fn supports(&self, user_hash: Option<[u8; 16]>, endpoint: SocketAddr) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        state.expire(Instant::now());
        state
            .connection_for(user_hash, endpoint)
            .and_then(|id| state.connections.get(&id))
            .is_some_and(|conn| conn.allows && !conn.abandoned)
    }

    pub fn pending(&self, user_hash: Option<[u8; 16]>, endpoint: SocketAddr) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        state.expire(Instant::now());
        state
            .connection_for(user_hash, endpoint)
            .and_then(|id| state.connections.get(&id))
            .is_some_and(|conn| conn.pending.is_some())
    }

    pub fn start(
        &self,
        user_hash: Option<[u8; 16]>,
        endpoint: SocketAddr,
    ) -> Result<PeerBrowseStart> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("peer browse registry unavailable"))?;
        let now = Instant::now();
        state.expire(now);
        let connection = state
            .connection_for(user_hash, endpoint)
            .context("no established browse connection for source")?;
        let conn = &state.connections[&connection];
        if let Some(search_id) = conn.pending {
            return Ok(PeerBrowseStart {
                search_id,
                already_pending: true,
            });
        }
        ensure!(
            conn.allows && !conn.abandoned,
            "peer shared-file browsing unavailable on this connection"
        );
        let peer = conn.peer;
        let strings = conn.strings;
        if state.searches.len() >= MAX_SEARCHES {
            ensure!(state.evict_finished(), "too many pending peer browses");
        }
        let search_id = state
            .next_id()
            .context("browse identifier space exhausted")?;
        let conn = state
            .connections
            .get_mut(&connection)
            .expect("established connection");
        // A timed-out command which never reached the wire can be replaced safely.
        conn.commands.send_replace(Some(search_id));
        conn.pending = Some(search_id);
        state.searches.insert(
            search_id,
            Record {
                connection,
                peer,
                strings,
                status: PeerBrowseStatus::Pending,
                phase: Phase::Queued,
                touched: now,
                chunks: VecDeque::new(),
                total: 0,
                bytes: 0,
                revision: 0,
            },
        );
        Ok(PeerBrowseStart {
            search_id,
            already_pending: false,
        })
    }

    pub fn page(&self, search_id: u64, offset: usize, limit: usize) -> Option<PeerBrowsePage> {
        let mut state = self.state.lock().ok()?;
        state.expire(Instant::now());
        state.page(search_id, offset, limit)
    }

    pub fn page_for_peer(
        &self,
        user_hash: Option<[u8; 16]>,
        endpoint: SocketAddr,
        search_id: u64,
        offset: usize,
        limit: usize,
    ) -> Option<PeerBrowsePage> {
        let mut state = self.state.lock().ok()?;
        state.expire(Instant::now());
        let record = state.searches.get(&search_id)?;
        if !record.peer.matches(user_hash, endpoint) {
            return None;
        }
        state.page(search_id, offset, limit)
    }
}

/// Owned by one established session, including while it services alternate files.
pub(crate) struct PeerBrowseSession {
    registry: PeerBrowseRegistry,
    id: u64,
    rx: watch::Receiver<Option<u64>>,
}

impl Drop for PeerBrowseSession {
    fn drop(&mut self) {
        if let Ok(mut state) = self.registry.state.lock()
            && let Some(conn) = state.connections.remove(&self.id)
            && let Some(id) = conn.pending
        {
            state.finish(id, PeerBrowseStatus::Disconnected, Instant::now());
        }
    }
}

impl PeerBrowseSession {
    pub(crate) fn update(
        &self,
        allows_browse: bool,
        supports_dirs: bool,
        strings: Ed2kStringEncoding,
    ) {
        if let Ok(mut state) = self.registry.state.lock()
            && let Some(conn) = state.connections.get_mut(&self.id)
        {
            conn.allows = allows_browse;
            conn.dirs = supports_dirs;
            conn.strings = strings;
        }
    }

    fn take_command(&self, id: u64) -> Option<Vec<u8>> {
        let mut state = self.registry.state.lock().ok()?;
        let now = Instant::now();
        state.expire(now);
        let conn = state.connections.get(&self.id)?;
        if conn.pending != Some(id) {
            return None;
        }
        if !conn.allows {
            state.finish(id, PeerBrowseStatus::Denied, now);
            return None;
        }
        let dirs = conn.dirs;
        let strings = conn.strings;
        let r = state.searches.get_mut(&id)?;
        r.strings = strings;
        r.phase = if dirs {
            Phase::Directories
        } else {
            Phase::Flat
        };
        r.touched = now;
        Some(encode_packet(
            OP_EDONKEYPROT,
            if dirs {
                OP_ASKSHAREDDIRS
            } else {
                OP_ASKSHAREDFILES
            },
            &[],
        ))
    }

    pub(crate) async fn recv(&mut self) -> Option<Vec<u8>> {
        while self.rx.changed().await.is_ok() {
            let id = (*self.rx.borrow_and_update())?;
            if let Some(frame) = self.take_command(id) {
                return Some(frame);
            }
        }
        None
    }

    #[cfg(test)]
    fn try_recv(&mut self) -> Option<Vec<u8>> {
        while self.rx.has_changed().ok()? {
            let id = (*self.rx.borrow_and_update())?;
            if let Some(frame) = self.take_command(id) {
                return Some(frame);
            }
        }
        None
    }

    /// Decode an owned peer packet off the async runtime, preserving its original allocation.
    pub(crate) async fn handle_reply_async(&self, opcode: u8, payload: Vec<u8>) -> Option<Vec<u8>> {
        let target = self.registry.reply_target(self.id)?;
        let registry = self.registry.clone();
        if opcode == OP_ASKSHAREDDENIEDANS {
            return registry.apply_reply(target, opcode, &payload);
        }
        tokio::task::spawn_blocking(move || registry.apply_reply(target, opcode, &payload))
            .await
            .ok()
            .flatten()
    }

    #[cfg(test)]
    fn handle_reply(&self, opcode: u8, payload: &[u8]) -> Option<Vec<u8>> {
        self.registry
            .apply_reply(self.registry.reply_target(self.id)?, opcode, payload)
    }
}

#[derive(Clone, Copy)]
struct ReplyTarget {
    connection: u64,
    search: u64,
    revision: u64,
}

impl ReplyTarget {
    fn matches(self, state: &RegistryState) -> bool {
        state
            .connections
            .get(&self.connection)
            .is_some_and(|conn| conn.pending == Some(self.search))
            && state.searches.get(&self.search).is_some_and(|r| {
                r.status == PeerBrowseStatus::Pending && r.revision == self.revision
            })
    }
}

impl PeerBrowseRegistry {
    fn reply_target(&self, connection: u64) -> Option<ReplyTarget> {
        let mut state = self.state.lock().ok()?;
        state.expire(Instant::now());
        let search = state.connections.get(&connection)?.pending?;
        let record = state.searches.get(&search)?;
        if matches!(record.phase, Phase::Queued) {
            return None;
        }
        Some(ReplyTarget {
            connection,
            search,
            revision: record.revision,
        })
    }

    fn apply_reply(&self, target: ReplyTarget, opcode: u8, payload: &[u8]) -> Option<Vec<u8>> {
        let mut state = self.state.lock().ok()?;
        let now = Instant::now();
        state.expire(now);
        if !target.matches(&state) {
            return None;
        }
        let id = target.search;
        let r = state.searches.get(&id)?;
        if opcode == OP_ASKSHAREDDENIEDANS {
            state.finish(
                id,
                if payload.is_empty() {
                    PeerBrowseStatus::Denied
                } else {
                    PeerBrowseStatus::Malformed
                },
                now,
            );
            return None;
        }
        let strings = r.strings;
        let remaining = MAX_FILES - r.total;
        let (body, dir) = match (&r.phase, opcode) {
            (Phase::Flat, OP_ASKSHAREDFILESANSWER) => (payload, None),
            (Phase::Directories, OP_ASKSHAREDDIRSANS) => (payload, None),
            (Phase::Files(dirs), OP_ASKSHAREDFILESDIRANS) => {
                let Ok((raw, body)) = split_browse_directory(payload) else {
                    state.finish(id, PeerBrowseStatus::Malformed, now);
                    return None;
                };
                // Ignore an unsolicited directory without consuming the outstanding request.
                if dirs.front().map(Vec::as_slice) != Some(raw) {
                    return None;
                }
                (body, Some(raw))
            }
            _ => return None,
        };
        // Other peers and REST page readers do not wait while a full wire page is decoded.
        drop(state);
        let processed = if opcode == OP_ASKSHAREDDIRSANS {
            read_dirs(body)
        } else {
            read_files(body, strings, remaining, dir)
        };
        let mut state = self.state.lock().ok()?;
        let now = Instant::now();
        state.expire(now);
        if !target.matches(&state) {
            return None;
        }
        let chunk = match processed {
            Ok(chunk) => chunk,
            Err(status) => {
                state.finish(id, status, now);
                return None;
            }
        };
        if !state.reserve_bytes(id, chunk.charge()) {
            state.finish(id, PeerBrowseStatus::Limit, now);
            return None;
        }
        let r = state.searches.get_mut(&id)?;
        r.revision += 1;
        r.touched = now;
        match chunk {
            Received::Directories(dirs) => {
                r.phase = Phase::Files(dirs);
            }
            Received::Files(files, _) => {
                r.total += files.len();
                if !files.is_empty() {
                    r.chunks.push_back(files);
                }
                if let Phase::Files(dirs) = &mut r.phase {
                    dirs.pop_front();
                }
            }
        }
        if let Phase::Files(dirs) = &r.phase
            && let Some(next) = dirs.front()
        {
            // All labels came from validated u16-length-prefixed wire strings.
            return encode_browse_dir_request(next).ok();
        }
        state.finish(id, PeerBrowseStatus::Complete, now);
        None
    }
}

enum Received {
    Directories(VecDeque<Vec<u8>>),
    Files(Box<[PeerBrowseResult]>, usize),
}

impl Received {
    fn charge(&self) -> usize {
        match self {
            // Include queue allocations and wire bytes even after the label has been consumed.
            Self::Directories(dirs) => {
                dirs.capacity() * size_of::<Vec<u8>>()
                    + dirs.iter().map(Vec::capacity).sum::<usize>()
            }
            Self::Files(_, cost) => *cost,
        }
    }
}

fn count(payload: &[u8], remaining: usize) -> Result<(), PeerBrowseStatus> {
    let raw: [u8; 4] = payload
        .get(..4)
        .ok_or(PeerBrowseStatus::Malformed)?
        .try_into()
        .map_err(|_| PeerBrowseStatus::Malformed)?;
    if u32::from_le_bytes(raw) as usize > remaining {
        return Err(PeerBrowseStatus::Limit);
    }
    Ok(())
}

fn read_dirs(payload: &[u8]) -> Result<Received, PeerBrowseStatus> {
    count(payload, MAX_DIRS)?;
    let dirs = decode_browse_dirs(payload, MAX_DIRS).map_err(|_| PeerBrowseStatus::Malformed)?;
    Ok(Received::Directories(dirs.into()))
}

fn read_files(
    payload: &[u8],
    strings: Ed2kStringEncoding,
    remaining: usize,
    raw_dir: Option<&[u8]>,
) -> Result<Received, PeerBrowseStatus> {
    count(payload, remaining)?;
    let files = decode_browse_files(payload, strings, remaining)
        .map_err(|_| PeerBrowseStatus::Malformed)?;
    let directory: Option<Arc<str>> = raw_dir
        .filter(|_| !files.is_empty())
        .map(|raw| strings.decode(raw).into());
    // Charge heap capacity for filenames, the result slice and shared directory string,
    // plus a conservative allowance for chunk and reference-count allocations.
    let charge = files
        .iter()
        .map(|file| file.display_name.capacity() + size_of::<PeerBrowseResult>())
        .sum::<usize>()
        + directory
            .as_ref()
            .map_or(0, |s| s.len() + 2 * size_of::<usize>())
        + 4 * size_of::<Box<[PeerBrowseResult]>>();
    let files = files
        .into_iter()
        .map(|file| PeerBrowseResult {
            directory: directory.clone(),
            file,
        })
        .collect();
    Ok(Received::Files(files, charge))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed2k_tcp::codec::shared_browse::{
        PeerBrowseEncoding, encode_browse_dirs, encode_browse_files,
    };
    use emulebb_kad_proto::Ed2kHash;

    const HASH: [u8; 16] = [3; 16];

    fn endpoint() -> SocketAddr {
        "192.0.2.15:4662".parse().unwrap()
    }

    fn session(registry: &PeerBrowseRegistry, dirs: bool) -> PeerBrowseSession {
        registry
            .register(HASH, endpoint(), true, dirs, Ed2kStringEncoding::Utf8)
            .unwrap()
    }

    fn response(directory: Option<&[u8]>, files: &[PeerBrowseFile]) -> Vec<u8> {
        encode_browse_files(
            files,
            directory,
            PeerBrowseEncoding {
                strings: Ed2kStringEncoding::Utf8,
                emule_family: true,
                compact_tags: true,
                local_endpoint: None,
                supports_large_files: true,
            },
        )
        .unwrap()
    }

    fn file(n: u64) -> PeerBrowseFile {
        let mut hash = [0u8; 16];
        hash[..8].copy_from_slice(&n.to_le_bytes());
        PeerBrowseFile {
            file_hash: Ed2kHash(hash),
            display_name: format!("Sample-{n:06}.pdf"),
            file_size: n + 1,
        }
    }

    #[tokio::test]
    async fn deduplicates_and_scopes_flat_results() {
        let reg = PeerBrowseRegistry::default();
        let mut guard = session(&reg, false);
        let id = reg.start(Some(HASH), endpoint()).unwrap().search_id;
        assert!(reg.pending(Some(HASH), endpoint()));
        let duplicate = reg.start(None, endpoint()).unwrap();
        assert_eq!(duplicate.search_id, id);
        assert!(duplicate.already_pending);
        let frame = response(None, &[file(1), file(2)]);
        assert!(guard.handle_reply(frame[5], &frame[6..]).is_none());
        assert_eq!(
            reg.page(id, 0, 10).unwrap().status,
            PeerBrowseStatus::Pending
        );
        assert_eq!(guard.recv().await.unwrap()[5], OP_ASKSHAREDFILES);
        let opcode = frame[5];
        let mut payload = frame;
        payload.drain(..6);
        assert!(guard.handle_reply_async(opcode, payload).await.is_none());
        let page = reg.page_for_peer(Some(HASH), endpoint(), id, 1, 8).unwrap();
        assert_eq!(page.total, 2);
        assert_eq!(page.status, PeerBrowseStatus::Complete);
        assert_eq!(page.files[0].file, file(2));
        assert!(!reg.pending(Some(HASH), endpoint()));
        assert!(
            reg.page_for_peer(Some([8; 16]), endpoint(), id, 0, 8)
                .is_none()
        );
    }

    #[test]
    fn raw_directory_echo_is_correlated_and_unsolicited_reply_is_ignored() {
        let reg = PeerBrowseRegistry::default();
        let mut guard = session(&reg, true);
        let id = reg.start(None, endpoint()).unwrap().search_id;
        assert_eq!(guard.try_recv().unwrap()[5], OP_ASKSHAREDDIRS);
        let first = vec![0xE9, 0x81];
        let second = b"More".to_vec();
        let dirs = encode_browse_dirs(&[first.clone(), second.clone()]).unwrap();
        let ask = guard.handle_reply(dirs[5], &dirs[6..]).unwrap();
        assert_eq!(split_browse_directory(&ask[6..]).unwrap().0, first);
        let wrong = response(Some(&second), &[file(7)]);
        assert!(guard.handle_reply(wrong[5], &wrong[6..]).is_none());
        assert_eq!(reg.page(id, 0, 1).unwrap().total, 0);
        let ans = response(Some(&first), &[file(3)]);
        let ask = guard.handle_reply(ans[5], &ans[6..]).unwrap();
        assert_eq!(split_browse_directory(&ask[6..]).unwrap().0, second);
        let ans = response(Some(&second), &[]);
        assert!(guard.handle_reply(ans[5], &ans[6..]).is_none());
        let page = reg.page(id, 0, 1).unwrap();
        assert_eq!(page.status, PeerBrowseStatus::Complete);
        assert_eq!(page.total, 1);
        assert_eq!(
            page.files[0].directory.as_deref(),
            Some(Ed2kStringEncoding::Utf8.decode(&first).as_str())
        );
    }

    #[test]
    fn expired_unsent_command_is_replaced_and_late_worker_cannot_publish() {
        let reg = PeerBrowseRegistry::default();
        let mut guard = session(&reg, false);
        let expired = reg.start(Some(HASH), endpoint()).unwrap().search_id;
        reg.state
            .lock()
            .unwrap()
            .searches
            .get_mut(&expired)
            .unwrap()
            .touched = Instant::now() - IDLE_TIMEOUT;
        let active = reg.start(Some(HASH), endpoint()).unwrap().search_id;
        assert_ne!(active, expired);
        assert_eq!(guard.try_recv().unwrap()[5], OP_ASKSHAREDFILES);
        let old_work = reg.reply_target(guard.id).unwrap();
        drop(guard);
        let mut replacement = session(&reg, false);
        let other = reg.start(Some(HASH), endpoint()).unwrap().search_id;
        assert!(replacement.try_recv().is_some());
        assert!(
            reg.apply_reply(old_work, OP_ASKSHAREDFILESANSWER, &0u32.to_le_bytes())
                .is_none()
        );
        assert_eq!(
            reg.page(expired, 0, 1).unwrap().status,
            PeerBrowseStatus::Timeout
        );
        assert_eq!(
            reg.page(active, 0, 1).unwrap().status,
            PeerBrowseStatus::Disconnected
        );
        assert_eq!(
            reg.page(other, 0, 1).unwrap().status,
            PeerBrowseStatus::Pending
        );
    }

    #[test]
    fn capability_denial_disconnect_timeout_and_stale_reply_are_distinct() {
        let reg = PeerBrowseRegistry::default();
        let mut guard = session(&reg, false);
        guard.update(false, false, Ed2kStringEncoding::Legacy);
        assert!(!reg.supports(Some(HASH), endpoint()));
        assert!(reg.start(Some(HASH), endpoint()).is_err());
        guard.update(true, false, Ed2kStringEncoding::Legacy);
        let id = reg.start(Some(HASH), endpoint()).unwrap().search_id;
        assert!(guard.try_recv().is_some());
        assert!(guard.handle_reply(OP_ASKSHAREDDENIEDANS, &[]).is_none());
        assert_eq!(reg.page(id, 0, 0).unwrap().status, PeerBrowseStatus::Denied);
        let id = reg.start(Some(HASH), endpoint()).unwrap().search_id;
        assert!(guard.try_recv().is_some());
        reg.state
            .lock()
            .unwrap()
            .searches
            .get_mut(&id)
            .unwrap()
            .touched = Instant::now() - IDLE_TIMEOUT;
        assert_eq!(
            reg.page(id, 0, 1).unwrap().status,
            PeerBrowseStatus::Timeout
        );
        assert!(reg.start(Some(HASH), endpoint()).is_err());
        assert!(
            guard
                .handle_reply(OP_ASKSHAREDFILESANSWER, &0u32.to_le_bytes())
                .is_none()
        );
        assert_eq!(
            reg.page(id, 0, 1).unwrap().status,
            PeerBrowseStatus::Timeout
        );
        let other = session(&reg, false);
        let id = reg.start(None, endpoint()).unwrap().search_id;
        drop(guard);
        assert_eq!(
            reg.page(id, 0, 1).unwrap().status,
            PeerBrowseStatus::Pending
        );
        drop(other);
        assert_eq!(
            reg.page(id, 0, 1).unwrap().status,
            PeerBrowseStatus::Disconnected
        );
    }

    #[test]
    fn preserves_malformed_and_budget_outcomes() {
        for (payload, expected) in [
            (vec![1], PeerBrowseStatus::Malformed),
            (
                (MAX_FILES as u32 + 1).to_le_bytes().to_vec(),
                PeerBrowseStatus::Limit,
            ),
        ] {
            let reg = PeerBrowseRegistry::default();
            let mut guard = session(&reg, false);
            let id = reg.start(None, endpoint()).unwrap().search_id;
            assert!(guard.try_recv().is_some());
            assert!(
                guard
                    .handle_reply(OP_ASKSHAREDFILESANSWER, &payload)
                    .is_none()
            );
            assert_eq!(reg.page(id, 0, 1).unwrap().status, expected);
        }
        let reg = PeerBrowseRegistry::default();
        let mut guard = session(&reg, false);
        let id = reg.start(None, endpoint()).unwrap().search_id;
        assert!(guard.try_recv().is_some());
        reg.state
            .lock()
            .unwrap()
            .searches
            .get_mut(&id)
            .unwrap()
            .bytes = RETAINED_BYTES;
        let frame = response(None, &[file(0)]);
        assert!(guard.handle_reply(frame[5], &frame[6..]).is_none());
        let page = reg.page(id, 0, 1).unwrap();
        assert_eq!(page.status, PeerBrowseStatus::Limit);
        assert!(page.files.is_empty());
    }

    #[test]
    fn pages_one_hundred_thousand_files_across_directory_replies() {
        let reg = PeerBrowseRegistry::default();
        let mut guard = session(&reg, true);
        let id = reg.start(None, endpoint()).unwrap().search_id;
        assert!(guard.try_recv().is_some());
        let labels: Vec<_> = (0..10)
            .map(|n| format!("Sample-{n}").into_bytes())
            .collect();
        let dirs = encode_browse_dirs(&labels).unwrap();
        let mut next = guard.handle_reply(dirs[5], &dirs[6..]);
        for (i, label) in labels.iter().enumerate() {
            let ask = next.take().unwrap();
            assert_eq!(split_browse_directory(&ask[6..]).unwrap().0, label);
            let first = (i * 10_000) as u64;
            let rows: Vec<_> = (first..first + 10_000).map(file).collect();
            let frame = response(Some(label), &rows);
            next = guard.handle_reply(frame[5], &frame[6..]);
        }
        assert!(next.is_none());
        let last = reg.page(id, 99_998, MAX_PAGE).unwrap();
        assert_eq!(last.total, 100_000);
        assert_eq!(last.status, PeerBrowseStatus::Complete);
        assert_eq!(last.files[1].file, file(99_999));
        assert_eq!(reg.page(id, 0, usize::MAX).unwrap().files.len(), MAX_PAGE);
    }
}
