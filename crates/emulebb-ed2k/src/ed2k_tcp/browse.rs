//! Catalog serving and browse commands share one protocol across peer directions.
mod catalog;
pub(crate) mod requests;

use std::{net::SocketAddr, time::Duration};

use anyhow::Result;
use emulebb_settings::product::SharedFilesVisibility;
use sha2::{Digest, Sha256};
use tokio::time::{Instant, error::Elapsed, timeout_at};

use crate::{ed2k_string::Ed2kStringEncoding, ed2k_transfer::Ed2kTransferRuntime};

use super::{
    Ed2kHelloIdentity, Ed2kPeerDispatcher, EmuleTcpPacket, OP_ASKSHAREDDIRS, OP_ASKSHAREDFILES,
    OP_ASKSHAREDFILESDIR,
    codec::{
        encode_empty_shared_files_answer, encode_shared_browse_denied_answer,
        shared_browse::{
            BrowseReplyTooLarge, PeerBrowseEncoding, encode_browse_dirs, encode_browse_files,
            split_browse_directory,
        },
    },
    hello::DecodedHelloProfile,
    identity::Ed2kPeerSecureIdentState,
};
use requests::PeerBrowseSession;

#[derive(Clone, Copy, Debug)]
pub(super) struct BrowsePeer {
    pub(super) allows_browse: bool,
    pub(super) supports_dirs: bool,
    listen_port: u16,
    encoding: PeerBrowseEncoding,
}

impl BrowsePeer {
    pub(super) fn from_hello(hello: &DecodedHelloProfile) -> Self {
        let emule_version = hello.emule_version_tag.filter(|tag| tag >> 24 == 0);
        let compact_tags = emule_version.is_some_and(|version| version >= ((42 << 10) | (7 << 7)));
        Self {
            allows_browse: !hello.misc_options1.no_view_shared_files,
            supports_dirs: hello.is_mule_hello,
            listen_port: hello.identity.tcp_port,
            encoding: PeerBrowseEncoding {
                strings: Ed2kStringEncoding::from_unicode_support(
                    hello.misc_options1.unicode_support,
                ),
                compact_tags,
                emule_family: emule_version.is_some(),
                supports_large_files: hello.supports_large_files,
                local_endpoint: None,
            },
        }
    }

    pub(super) fn bind(
        self,
        runtime: &Ed2kTransferRuntime,
        user_hash: [u8; 16],
        remote: SocketAddr,
        session: &mut Option<PeerBrowseSession>,
    ) {
        if let Some(session) = session {
            self.update(session);
            return;
        }
        let endpoint = if self.listen_port == 0 {
            remote
        } else {
            SocketAddr::new(remote.ip(), self.listen_port)
        };
        *session = runtime.peer_browse_registry().register(
            user_hash,
            endpoint,
            self.allows_browse,
            self.supports_dirs,
            self.encoding.strings,
        );
    }

    pub(super) fn update(self, session: &PeerBrowseSession) {
        session.update(
            self.allows_browse,
            self.supports_dirs,
            self.encoding.strings,
        );
    }
}

#[derive(Default)]
pub(super) struct BrowseConnection {
    pub(super) session: Option<PeerBrowseSession>,
    pub(super) serving: BrowseServing,
}

#[derive(Default)]
pub(super) struct BrowseServing {
    directories: Option<catalog::BrowseDirectories>,
}

#[derive(Clone, Copy)]
pub(super) struct BrowseIdentity<'a> {
    pub(super) user_hash: Option<[u8; 16]>,
    pub(super) secure_ident: &'a Ed2kPeerSecureIdentState,
}

impl BrowseServing {
    pub(super) async fn reply(
        &mut self,
        runtime: &Ed2kTransferRuntime,
        opcode: u8,
        request: &[u8],
        peer: BrowsePeer,
        local: Ed2kHelloIdentity,
        identity: BrowseIdentity<'_>,
    ) -> Result<Vec<u8>> {
        if !authorized(runtime, identity).await {
            self.directories = None;
            return Ok(denied(opcode));
        }
        let Some(_permit) = runtime.try_browse_catalog_read() else {
            return Ok(encode_shared_browse_denied_answer());
        };
        let mut encoding = peer.encoding;
        encoding.local_endpoint = Some((local.client_id, local.tcp_port));
        let encoded = match opcode {
            OP_ASKSHAREDFILES => match catalog::flat_files(runtime, encoding).await {
                Ok(files) => encode_browse_files(&files, None, encoding),
                Err(error) => Err(error),
            },
            OP_ASKSHAREDDIRS => {
                self.directories = None;
                match catalog::BrowseDirectories::build(runtime, encoding).await {
                    Ok(directories) => {
                        let encoded = encode_browse_dirs(directories.labels())?;
                        self.directories = Some(directories);
                        Ok(encoded)
                    }
                    Err(error) => Err(error),
                }
            }
            OP_ASKSHAREDFILESDIR => {
                let (raw_label, _) = split_browse_directory(request)?;
                let files = if let Some(directories) = &self.directories {
                    directories
                        .files(runtime, raw_label, encoding)
                        .await?
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                encode_browse_files(&files, Some(raw_label), encoding)
            }
            _ => unreachable!("share browse handler only serves request opcodes"),
        };
        if !authorized(runtime, identity).await {
            self.directories = None;
            return Ok(denied(opcode));
        }
        match encoded {
            Err(error) if error.is::<BrowseReplyTooLarge>() => {
                Ok(encode_shared_browse_denied_answer())
            }
            result => result,
        }
    }
}

fn denied(opcode: u8) -> Vec<u8> {
    if opcode == OP_ASKSHAREDFILES {
        encode_empty_shared_files_answer()
    } else {
        encode_shared_browse_denied_answer()
    }
}

async fn authorized(runtime: &Ed2kTransferRuntime, identity: BrowseIdentity<'_>) -> bool {
    match runtime.shared_files_visibility() {
        SharedFilesVisibility::Everyone => true,
        SharedFilesVisibility::Off => false,
        SharedFilesVisibility::Friends => {
            let Some((hash, key)) = identity.secure_ident.verified_browse_key() else {
                return false;
            };
            if identity.user_hash != Some(hash) {
                return false;
            }
            runtime
                .authorizes_friend_browse(hash, Sha256::digest(key).into())
                .await
        }
    }
}

pub(super) enum PeerOrBrowse {
    Packet(std::result::Result<Result<Option<EmuleTcpPacket>>, Elapsed>),
    Browse(Vec<u8>),
}

pub(super) async fn read_peer_or_browse(
    transport: &mut Ed2kPeerDispatcher,
    read_timeout: Duration,
    flow: &'static str,
    peer_addr: SocketAddr,
) -> PeerOrBrowse {
    let deadline = Instant::now() + read_timeout;
    let read = match timeout_at(deadline, transport.wait_for_input()).await {
        Ok(Ok(Some(frame))) => return PeerOrBrowse::Browse(frame),
        Ok(Ok(None)) => Ok(read_ready_packet(transport, deadline, flow, peer_addr).await),
        Ok(Err(error)) => Ok(Err(error.into())),
        Err(elapsed) => Err(elapsed),
    };
    PeerOrBrowse::Packet(read)
}

/// Completing the header and body advances the stream cipher. An assembly
/// timeout closes the connection instead of polling the partially read frame.
pub(super) async fn read_ready_packet(
    transport: &mut Ed2kPeerDispatcher,
    deadline: Instant,
    flow: &'static str,
    peer_addr: SocketAddr,
) -> Result<Option<EmuleTcpPacket>> {
    timeout_at(
        deadline,
        transport.read_packet_diagnostic(flow, peer_addr, "session"),
    )
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(hash: [u8; 16], session: &Ed2kPeerSecureIdentState) -> BrowseIdentity<'_> {
        BrowseIdentity {
            user_hash: Some(hash),
            secure_ident: session,
        }
    }

    #[tokio::test]
    async fn friends_visibility_needs_the_enrolled_signing_key_on_the_current_session() {
        let temp = tempfile::tempdir().unwrap();
        let store = emulebb_metadata::MetadataStore::in_memory().unwrap();
        let runtime =
            Ed2kTransferRuntime::load_or_create_with_metadata(temp.path(), store.clone()).unwrap();
        let hash = [0x42; 16];
        let friend = emulebb_metadata::MetadataFriend {
            user_hash: hex::encode(hash),
            name: "Trusted peer".into(),
            last_address: None,
            last_port: 0,
            first_seen_s: 0,
            last_seen_s: None,
        };
        let mut session = Ed2kPeerSecureIdentState::default();
        assert!(authorized(&runtime, identity(hash, &session)).await);
        runtime.set_shared_files_visibility(SharedFilesVisibility::Friends);
        store.upsert_friend(&friend).unwrap();

        let public_key = vec![1, 2, 3];
        session.peer_public_key = Some(public_key.clone());
        session.pinned_public_key = Some(public_key.clone());
        session.peer_ident_verified = true;
        session.verified_user_hash = Some(hash);
        assert!(
            !authorized(&runtime, identity(hash, &session)).await,
            "TOFU is insufficient"
        );
        store
            .upsert_friend_with_browse_key(&friend, Some(Sha256::digest(&public_key).into()))
            .unwrap();
        assert!(authorized(&runtime, identity(hash, &session)).await);
        assert!(!authorized(&runtime, identity([0x43; 16], &session)).await);

        session.peer_ident_verified = false;
        assert!(!authorized(&runtime, identity(hash, &session)).await);
        session.peer_ident_verified = true;
        runtime.set_shared_files_visibility(SharedFilesVisibility::Off);
        assert!(!authorized(&runtime, identity(hash, &session)).await);
        runtime.set_shared_files_visibility(SharedFilesVisibility::Friends);
        store.delete_friend(&friend.user_hash).unwrap();
        store.upsert_friend(&friend).unwrap();
        assert!(
            !authorized(&runtime, identity(hash, &session)).await,
            "removal revokes the enrolled key"
        );
    }
}
