//! Listener-session secure-identification handlers (OP_SECIDENTSTATE,
//! OP_PUBLICKEY, OP_SIGNATURE). These drive the eMule SUI challenge/response on
//! an inbound connection: send our public key + signature on demand, probe the
//! peer for its credential, and RSA-verify the peer's returned signature,
//! syncing the verdict onto the upload identity so credit attribution and the
//! IS_IDBADGUY penalty follow the verification result.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::debug;

use crate::ed2k_transfer::{Ed2kTransferRuntime, Ed2kUploadPeerIdentity};

use super::super::super::dump::{dump_ed2k_tcp_listener_meta, dump_ed2k_tcp_listener_send};
use super::super::super::identity::{
    Ed2kPeerSecureIdentState, decode_public_key_payload, decode_secident_state,
    decode_signature_payload, encode_secident_state, random_nonzero_u32,
    try_send_secure_ident_signature, verify_peer_secure_ident_signature,
};
use super::super::super::{
    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, ED2K_SECURE_IDENT_SIGNATURE_NEEDED,
    Ed2kSecureIdent, Ed2kTransport, OP_EMULEPROT, OP_PUBLICKEY, encode_packet,
};

/// OP_SECIDENTSTATE: the peer told us which credential it needs; send the
/// public key when requested, then try to send our signature, falling back to
/// a fresh probe when the peer needs ours.
pub(super) async fn handle_secident_state(
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    secure_ident: &Arc<Ed2kSecureIdent>,
    peer_secure_ident: &mut Ed2kPeerSecureIdentState,
    payload: &[u8],
) -> Result<()> {
    let (state, challenge) = decode_secident_state(payload)?;
    debug!(
        "received eMule OP_SECIDENTSTATE from {peer_addr} transport={} state={} challenge={challenge}",
        transport.mode.as_str(),
        state
    );
    peer_secure_ident.peer_challenge_from = Some(challenge);
    if state != 0 {
        peer_secure_ident.pending_signature = true;
    }
    if state == ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED {
        let public_key = encode_packet(
            OP_EMULEPROT,
            OP_PUBLICKEY,
            &secure_ident.public_key_payload()?,
        );
        dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "public_key", &public_key);
        transport
            .write_all(&public_key)
            .await
            .with_context(|| format!("failed to send OP_PUBLICKEY to {peer_addr}"))?;
    }
    if !try_send_secure_ident_signature(
        transport,
        peer_addr,
        secure_ident,
        peer_secure_ident,
        "listener",
    )
    .await?
        && state == ED2K_SECURE_IDENT_SIGNATURE_NEEDED
        && !peer_secure_ident.requested_peer_key
    {
        let challenge_for = random_nonzero_u32();
        peer_secure_ident.challenge_for = Some(challenge_for);
        peer_secure_ident.pending_signature = true;
        peer_secure_ident.requested_peer_key = true;
        let request =
            encode_secident_state(ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, challenge_for);
        dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "secure_ident_probe", &request);
        transport
            .write_all(&request)
            .await
            .with_context(|| format!("failed to send fallback OP_SECIDENTSTATE to {peer_addr}"))?;
    }
    Ok(())
}

/// OP_PUBLICKEY: record the peer's public key and (re)attempt to send our
/// signature now that we can frame the challenge.
pub(super) async fn handle_public_key(
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    secure_ident: &Arc<Ed2kSecureIdent>,
    peer_secure_ident: &mut Ed2kPeerSecureIdentState,
    payload: &[u8],
) -> Result<()> {
    peer_secure_ident.peer_public_key = Some(decode_public_key_payload(payload)?);
    debug!(
        "received eMule OP_PUBLICKEY from {peer_addr} transport={} key_len={}",
        transport.mode.as_str(),
        peer_secure_ident
            .peer_public_key
            .as_ref()
            .map_or(0, Vec::len)
    );
    let _ = try_send_secure_ident_signature(
        transport,
        peer_addr,
        secure_ident,
        peer_secure_ident,
        "listener",
    )
    .await?;
    Ok(())
}

/// OP_SIGNATURE: RSA-verify the peer's signature against the challenge we
/// issued (supplying our external IP for V2 challenge-IP reconstruction),
/// record the verdict, and sync it onto the upload identity so credit only
/// benefits a verified peer (IS_IDENTIFIED) and a FAILED verify marks the peer
/// IS_IDBADGUY (its upload score is zeroed, not merely denied the credit).
#[allow(clippy::too_many_arguments)]
pub(super) fn handle_signature(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    secure_ident: &Arc<Ed2kSecureIdent>,
    peer_secure_ident: &mut Ed2kPeerSecureIdentState,
    peer_upload_identity: &mut Ed2kUploadPeerIdentity,
    transfer_runtime: &Ed2kTransferRuntime,
    external_ip: Option<Ipv4Addr>,
    payload: &[u8],
) {
    match decode_signature_payload(payload) {
        Ok(signature) => {
            let verified = verify_peer_secure_ident_signature(
                secure_ident,
                peer_secure_ident,
                &signature,
                peer_addr,
                external_ip,
            );
            // On a successful verify, bind the peer's pubkey to its credit row
            // (wiping credits if a different key verified for this user hash
            // before -- eMule CClientCredits::Verified anti-takeover).
            if verified {
                bind_verified_pubkey(transfer_runtime, peer_secure_ident, peer_upload_identity);
            }
            dump_ed2k_tcp_listener_meta(
                peer_addr,
                Some(transport.mode),
                if verified {
                    "secure_ident_signature_verified"
                } else {
                    "secure_ident_signature_unverified"
                },
                || (format!(
                    "signature_len={} challenge_ip_kind={} verified={verified}",
                    signature.signature_len,
                    signature
                        .challenge_ip_kind
                        .map(|kind| kind.to_string())
                        .unwrap_or_else(|| "none".to_string())
                )).into(),
            );
            peer_upload_identity.ident_verified = verified;
            peer_upload_identity.ident_bad_guy = !verified;
        }
        Err(error) => {
            dump_ed2k_tcp_listener_meta(
                peer_addr,
                Some(transport.mode),
                "secure_ident_signature_invalid",
                || (format!("error={error:#}")).into(),
            );
        }
    }
}

/// Bind the just-verified peer pubkey to its credit row (eMule
/// `CClientCredits::Verified`). Requires both the peer's user hash (from the
/// hello) and its public key (from OP_PUBLICKEY); a missing either is a no-op.
fn bind_verified_pubkey(
    transfer_runtime: &Ed2kTransferRuntime,
    peer_secure_ident: &Ed2kPeerSecureIdentState,
    peer_upload_identity: &Ed2kUploadPeerIdentity,
) {
    let (Some(user_hash), Some(public_key)) = (
        peer_upload_identity.user_hash,
        peer_secure_ident.peer_public_key.as_deref(),
    ) else {
        return;
    };
    if let Err(error) = transfer_runtime.record_verified_secure_ident(user_hash, public_key) {
        debug!("failed to bind verified secure-ident pubkey: {error:#}");
    }
}
