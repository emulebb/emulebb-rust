use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
};

use emulebb_ed2k::ed2k_server::Ed2kFoundSource;

/// File-scoped source candidate retained by the peer-centric download registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DownloadSourceCandidate {
    pub file_hash: String,
    pub file_priority: u32,
    pub needed_parts: u32,
    pub rare_parts: u32,
    pub source: Ed2kFoundSource,
}

/// In-memory source registry that derives A4AF state from peer ownership.
#[derive(Debug, Default)]
pub(crate) struct DownloadSourceRegistry {
    peers: HashMap<DownloadPeerKey, Vec<DownloadSourceCandidate>>,
    leased_peers: HashSet<DownloadPeerKey>,
}

impl DownloadSourceRegistry {
    pub(crate) fn add_candidate(&mut self, candidate: DownloadSourceCandidate) {
        let candidates = self
            .peers
            .entry(DownloadPeerKey::from_source(&candidate.source))
            .or_default();
        if let Some(existing) = candidates
            .iter_mut()
            .find(|existing| existing.file_hash == candidate.file_hash)
        {
            *existing = candidate;
        } else {
            candidates.push(candidate);
        }
    }

    #[cfg(test)]
    pub(crate) fn candidate_count_for_peer(&self, source: &Ed2kFoundSource) -> usize {
        self.peers
            .get(&DownloadPeerKey::from_source(source))
            .map_or(0, Vec::len)
    }

    pub(crate) fn candidate_count(&self) -> usize {
        self.peers.values().map(Vec::len).sum()
    }

    pub(crate) fn a4af_candidate_count(&self) -> usize {
        self.peers
            .values()
            .filter(|candidates| candidates.len() > 1)
            .map(|candidates| candidates.len().saturating_sub(1))
            .sum()
    }

    pub(crate) fn leased_peer_count(&self) -> usize {
        self.leased_peers.len()
    }

    pub(crate) fn lease_best_for_file(
        &mut self,
        source: &Ed2kFoundSource,
        file_hash: &str,
    ) -> Option<DownloadSourceCandidate> {
        let peer_key = DownloadPeerKey::from_source(source);
        let candidates = self.peers.get(&peer_key)?;
        let candidate = candidates.iter().max_by_key(candidate_score)?;
        if candidate.file_hash != file_hash || !self.leased_peers.insert(peer_key) {
            return None;
        }
        Some(candidate.clone())
    }

    pub(crate) fn release_peer(&mut self, source: &Ed2kFoundSource) {
        self.leased_peers
            .remove(&DownloadPeerKey::from_source(source));
    }

    pub(crate) fn release_endpoint(&mut self, endpoint: (Ipv4Addr, u16)) {
        self.leased_peers
            .retain(|peer| (peer.ip, peer.tcp_port) != endpoint);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DownloadPeerKey {
    ip: Ipv4Addr,
    tcp_port: u16,
    user_hash: Option<[u8; 16]>,
    client_id: u32,
}

impl DownloadPeerKey {
    fn from_source(source: &Ed2kFoundSource) -> Self {
        Self {
            ip: source.ip,
            tcp_port: source.tcp_port,
            user_hash: source.user_hash,
            client_id: source.client_id,
        }
    }
}

fn candidate_score(candidate: &&DownloadSourceCandidate) -> (u32, u32, u32) {
    (
        candidate.file_priority,
        candidate.rare_parts,
        candidate.needed_parts,
    )
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use emulebb_ed2k::ed2k_server::Ed2kFoundSource;
    use emulebb_kad_proto::Ed2kHash;

    use super::{DownloadSourceCandidate, DownloadSourceRegistry};

    #[test]
    fn registry_derives_a4af_candidates_from_peer_fanout() {
        let source = source_with_hash([0x11; 16]);
        let mut registry = DownloadSourceRegistry::default();

        registry.add_candidate(candidate(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            1,
            1,
            source.clone(),
        ));
        registry.add_candidate(candidate(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            2,
            1,
            source.clone(),
        ));

        assert_eq!(registry.candidate_count_for_peer(&source), 2);
        assert_eq!(registry.a4af_candidate_count(), 1);
    }

    #[test]
    fn registry_leases_one_file_per_peer_and_prefers_best_candidate() {
        let source = source_with_hash([0x22; 16]);
        let mut registry = DownloadSourceRegistry::default();
        registry.add_candidate(candidate(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            1,
            10,
            source.clone(),
        ));
        registry.add_candidate(candidate(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            5,
            1,
            source.clone(),
        ));

        let leased = registry
            .lease_best_for_file(&source, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .unwrap();

        assert_eq!(leased.file_hash, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert!(
            registry
                .lease_best_for_file(&source, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .is_none()
        );
        registry.release_peer(&source);
        assert!(
            registry
                .lease_best_for_file(&source, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .is_some()
        );
    }

    #[test]
    fn registry_defers_when_peer_is_better_for_another_file() {
        let source = source_with_hash([0x33; 16]);
        let mut registry = DownloadSourceRegistry::default();
        registry.add_candidate(candidate(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            1,
            10,
            source.clone(),
        ));
        registry.add_candidate(candidate(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            5,
            1,
            source.clone(),
        ));

        assert!(
            registry
                .lease_best_for_file(&source, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .is_none()
        );
        assert!(
            registry
                .lease_best_for_file(&source, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .is_some()
        );
    }

    fn candidate(
        file_hash: &str,
        file_priority: u32,
        rare_parts: u32,
        source: Ed2kFoundSource,
    ) -> DownloadSourceCandidate {
        DownloadSourceCandidate {
            file_hash: file_hash.to_string(),
            file_priority,
            needed_parts: 4,
            rare_parts,
            source,
        }
    }

    fn source_with_hash(user_hash: [u8; 16]) -> Ed2kFoundSource {
        Ed2kFoundSource {
            file_hash: Ed2kHash::from_bytes([0x44; 16]),
            ip: Ipv4Addr::new(198, 51, 100, 40),
            tcp_port: 4662,
            client_id: 0xC633_6428,
            low_id: false,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: Some(user_hash),
            source_server: None,
            buddy_id: None,
            buddy_endpoint: None,
        }
    }
}
