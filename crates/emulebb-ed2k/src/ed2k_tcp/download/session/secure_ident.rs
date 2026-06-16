//! Download-session secure-identification handlers (OP_SECIDENTSTATE,
//! OP_PUBLICKEY, OP_SIGNATURE). These drive the eMule SUI challenge/response:
//! send our public key + signature on demand, and RSA-verify the uploader's
//! returned signature for the diagnostic dump.

use std::net::SocketAddr;

use anyhow::{Context, Result};

use crate::ed2k_tcp::{
    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, ED2K_SECURE_IDENT_SIGNATURE_NEEDED, Ed2kSecureIdent,
    Ed2kTransport, OP_EMULEPROT, OP_PUBLICKEY, begin_secure_ident_probe, decode_public_key_payload,
    decode_secident_state, decode_signature_payload, dump_ed2k_tcp_download_meta,
    dump_ed2k_tcp_download_send, encode_packet, try_send_secure_ident_signature,
    verify_peer_secure_ident_signature,
};

use super::state::DownloadSessionState;

/// OP_SECIDENTSTATE: the peer told us which credential (key and/or signature)
/// it needs; send the public key when requested, then try to send our
/// signature, falling back to a fresh probe when the peer needs ours.
pub(super) async fn handle_secident_state(
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    secure_ident: &Ed2kSecureIdent,
    session_state: &mut DownloadSessionState,
    payload: &[u8],
) -> Result<()> {
    let (state, challenge) = decode_secident_state(payload)?;
    session_state.peer_secure_ident.peer_challenge_from = Some(challenge);
    if state != 0 {
        session_state.peer_secure_ident.pending_signature = true;
    }
    if state == ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED {
        let public_key = encode_packet(
            OP_EMULEPROT,
            OP_PUBLICKEY,
            &secure_ident.public_key_payload()?,
        );
        dump_ed2k_tcp_download_send(peer_addr, transport.mode, "public_key", &public_key);
        transport
            .write_all(&public_key)
            .await
            .with_context(|| format!("failed to send OP_PUBLICKEY to {peer_addr}"))?;
    }
    if !try_send_secure_ident_signature(
        transport,
        peer_addr,
        secure_ident,
        &mut session_state.peer_secure_ident,
    )
    .await?
        && state == ED2K_SECURE_IDENT_SIGNATURE_NEEDED
        && !session_state.peer_secure_ident.requested_peer_key
    {
        let secure_ident_probe = begin_secure_ident_probe(&mut session_state.peer_secure_ident);
        dump_ed2k_tcp_download_send(
            peer_addr,
            transport.mode,
            "secure_ident_probe",
            &secure_ident_probe,
        );
        transport
            .write_all(&secure_ident_probe)
            .await
            .with_context(|| format!("failed to send fallback OP_SECIDENTSTATE to {peer_addr}"))?;
        session_state.secure_ident_started = true;
    }
    Ok(())
}

/// OP_PUBLICKEY: record the peer's public key and (re)attempt to send our
/// signature now that we can frame the challenge.
pub(super) async fn handle_public_key(
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    secure_ident: &Ed2kSecureIdent,
    session_state: &mut DownloadSessionState,
    payload: &[u8],
) -> Result<()> {
    session_state.peer_secure_ident.peer_public_key = Some(decode_public_key_payload(payload)?);
    let _ = try_send_secure_ident_signature(
        transport,
        peer_addr,
        secure_ident,
        &mut session_state.peer_secure_ident,
    )
    .await?;
    Ok(())
}

/// OP_SIGNATURE: RSA-verify the uploader's signature against the challenge we
/// issued and record the verified/unverified verdict in the diagnostic dump.
/// We have no learned external IP on this outbound path, so a V2 REMOTECLIENT
/// signature verifies only when the peer could know its own IP (eMule behaves
/// the same when LocalIP is unknown).
pub(super) fn handle_signature(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    secure_ident: &Ed2kSecureIdent,
    session_state: &mut DownloadSessionState,
    payload: &[u8],
) {
    match decode_signature_payload(payload) {
        Ok(signature) => {
            let verified = verify_peer_secure_ident_signature(
                secure_ident,
                &mut session_state.peer_secure_ident,
                &signature,
                peer_addr,
                None,
            );
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport.mode),
                if verified {
                    "secure_ident_signature_verified"
                } else {
                    "secure_ident_signature_unverified"
                },
                format!(
                    "signature_len={} challenge_ip_kind={} verified={verified}",
                    signature.signature_len,
                    signature
                        .challenge_ip_kind
                        .map(|kind| kind.to_string())
                        .unwrap_or_else(|| "none".to_string())
                ),
            );
        }
        Err(error) => {
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport.mode),
                "secure_ident_signature_invalid",
                format!("error={error:#}"),
            );
        }
    }
}
