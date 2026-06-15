use std::{
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
};

use anyhow::{Context, Result};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::DecodeRsaPublicKey,
    pkcs1v15::{Signature, SigningKey, VerifyingKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    rand_core::OsRng,
    signature::{RandomizedSigner, SignatureEncoding, Verifier},
};
use sha1::Sha1;

use super::{
    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, ED2K_SECURE_IDENT_KEY_BITS, Ed2kTransport,
    OP_EMULEPROT, OP_SECIDENTSTATE, OP_SIGNATURE, encode_packet,
};

/// Persistent RSA identity used for the eMule secure-ident side channel.
#[derive(Debug)]
pub struct Ed2kSecureIdent {
    pub(super) private_key: RsaPrivateKey,
    public_key_der: Vec<u8>,
}

impl Ed2kSecureIdent {
    /// Load the oracle-compatible ED2K secure-ident keypair from disk or create it on first use.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let bytes =
                fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
            return Self::from_pkcs8_der(&bytes).with_context(|| {
                format!("invalid PKCS#8 ED2K secure-ident key at {}", path.display())
            });
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let identity = Self::generate()?;
        let encoded = identity.to_pkcs8_der()?;
        fs::write(path, &encoded).with_context(|| format!("failed to write {}", path.display()))?;
        Ok(identity)
    }

    pub fn generate() -> Result<Self> {
        let private_key = RsaPrivateKey::new(&mut OsRng, ED2K_SECURE_IDENT_KEY_BITS)
            .context("failed to generate ED2K secure-ident RSA keypair")?;
        Self::from_private_key(private_key)
    }

    pub fn from_pkcs8_der(bytes: &[u8]) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_der(bytes)
            .context("invalid PKCS#8 ED2K secure-ident private key")?;
        Self::from_private_key(private_key)
    }

    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        Ok(self
            .private_key
            .to_pkcs8_der()
            .context("failed to encode ED2K secure-ident private key")?
            .as_bytes()
            .to_vec())
    }

    pub(super) fn from_private_key(private_key: RsaPrivateKey) -> Result<Self> {
        let public_key_der = RsaPublicKey::from(&private_key)
            .to_public_key_der()
            .context("failed to encode ED2K secure-ident public key")?
            .as_bytes()
            .to_vec();
        Ok(Self {
            private_key,
            public_key_der,
        })
    }

    /// Our SPKI DER public key bytes — the exact bytes we send in `OP_PUBLICKEY`,
    /// so an inbound signature must be verified over them (eMule signs over the
    /// recipient's public key, `m_abyMyPublicKey`).
    pub(super) fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }

    pub(super) fn public_key_payload(&self) -> Result<Vec<u8>> {
        let key_len = u8::try_from(self.public_key_der.len())
            .context("ED2K secure-ident public key exceeds u8 length")?;
        let mut payload = Vec::with_capacity(1 + self.public_key_der.len());
        payload.push(key_len);
        payload.extend_from_slice(&self.public_key_der);
        Ok(payload)
    }

    pub(super) fn signature_payload(
        &self,
        peer_public_key: &[u8],
        challenge: u32,
    ) -> Result<Vec<u8>> {
        let mut message = Vec::with_capacity(peer_public_key.len() + 4);
        message.extend_from_slice(peer_public_key);
        message.extend_from_slice(&challenge.to_le_bytes());

        let signing_key = SigningKey::<Sha1>::new(self.private_key.clone());
        let signature = signing_key.sign_with_rng(&mut OsRng, &message);
        let signature_bytes = signature.to_bytes();
        let sig_len = u8::try_from(signature_bytes.len())
            .context("ED2K secure-ident signature exceeds u8 length")?;
        let mut payload = Vec::with_capacity(1 + signature_bytes.len());
        payload.push(sig_len);
        payload.extend_from_slice(signature_bytes.as_ref());
        Ok(payload)
    }
}

#[derive(Debug, Default)]
pub(super) struct Ed2kPeerSecureIdentState {
    pub(super) peer_public_key: Option<Vec<u8>>,
    pub(super) peer_challenge_from: Option<u32>,
    pub(super) challenge_for: Option<u32>,
    pub(super) pending_signature: bool,
    pub(super) peer_signature_received: bool,
    /// Set only after [`verify_inbound_signature`] succeeds: the peer's user hash
    /// (and thus its credit-store identity) is cryptographically proven. eMule's
    /// `IS_IDENTIFIED`. Credits must only be attributed when this is true.
    pub(super) peer_ident_verified: bool,
    pub(super) requested_peer_key: bool,
}

pub(super) fn encode_secident_state(state: u8, challenge: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(5);
    payload.push(state);
    payload.extend_from_slice(&challenge.to_le_bytes());
    encode_packet(OP_EMULEPROT, OP_SECIDENTSTATE, &payload)
}

pub(super) fn decode_secident_state(payload: &[u8]) -> Result<(u8, u32)> {
    if payload.len() != 5 {
        anyhow::bail!("invalid OP_SECIDENTSTATE payload size {}", payload.len());
    }
    Ok((
        payload[0],
        u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]),
    ))
}

pub(super) fn decode_public_key_payload(payload: &[u8]) -> Result<Vec<u8>> {
    let Some((&key_len, key_bytes)) = payload.split_first() else {
        anyhow::bail!("empty OP_PUBLICKEY payload");
    };
    if usize::from(key_len) != key_bytes.len() {
        anyhow::bail!(
            "invalid OP_PUBLICKEY length prefix {} for payload size {}",
            key_len,
            key_bytes.len()
        );
    }
    Ok(key_bytes.to_vec())
}

/// eMule secure-ident V2 challenge-IP kinds (`ClientCredits.h` `CRYPT_CIP_*`):
/// they select which IP the signer folded into the signed message so a captured
/// V1 signature cannot be replayed against a different endpoint.
pub(super) const CRYPT_CIP_REMOTECLIENT: u8 = 10;
pub(super) const CRYPT_CIP_LOCALCLIENT: u8 = 20;
pub(super) const CRYPT_CIP_NONECLIENT: u8 = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SecureIdentSignature {
    pub(super) signature_len: u8,
    pub(super) challenge_ip_kind: Option<u8>,
    /// The raw RSA signature bytes (the payload after the length prefix, before
    /// any V2 ip-kind trailer), retained so the caller can RSA-verify it.
    pub(super) signature: Vec<u8>,
}

pub(super) fn decode_signature_payload(payload: &[u8]) -> Result<SecureIdentSignature> {
    if !(10..=250).contains(&payload.len()) {
        anyhow::bail!("invalid OP_SIGNATURE payload size {}", payload.len());
    }
    let signature_len = payload[0];
    let challenge_ip_kind = if usize::from(signature_len) == payload.len() - 1 {
        None
    } else if usize::from(signature_len) == payload.len() - 2 {
        payload.last().copied()
    } else {
        anyhow::bail!(
            "invalid OP_SIGNATURE length prefix {} for payload size {}",
            signature_len,
            payload.len()
        );
    };
    let signature = payload[1..1 + usize::from(signature_len)].to_vec();
    Ok(SecureIdentSignature {
        signature_len,
        challenge_ip_kind,
        signature,
    })
}

/// Parse a peer's secure-ident public key. eMule serializes the RSA public key
/// with Crypto++ `GetMaterial().Save()` (a bare PKCS#1 `RSAPublicKey` DER, no
/// SPKI `AlgorithmIdentifier` wrapper — it must fit `MAXPUBKEYSIZE` = 80 bytes),
/// while our own `Ed2kSecureIdent` emits SPKI. Accept either so we interoperate
/// with stock eMule peers and our own clients.
fn parse_peer_public_key(bytes: &[u8]) -> Result<RsaPublicKey> {
    if let Ok(key) = RsaPublicKey::from_pkcs1_der(bytes) {
        return Ok(key);
    }
    RsaPublicKey::from_public_key_der(bytes)
        .context("peer secure-ident public key is neither PKCS#1 nor SPKI DER")
}

/// Reconstruct the challenge IP a V2 signer folded into the signed message,
/// mirroring `CClientCreditsList::VerifyIdent`. The bytes match eMule's
/// `PokeUInt32(network-order IP)` on a little-endian host, which is the dotted
/// octets in natural order.
fn challenge_ip_bytes(
    ip_kind: u8,
    peer_ip: Ipv4Addr,
    our_external_ip: Option<Ipv4Addr>,
) -> Option<[u8; 4]> {
    match ip_kind {
        // The peer is HighID and signed with its own (server-assigned) IP, which
        // is exactly our view of the peer's IP.
        CRYPT_CIP_LOCALCLIENT => Some(peer_ip.octets()),
        // The peer was LowID and could not know its own IP, so it signed with
        // ours; reconstruct with our own external IP (eMule: GetClientID/LocalIP).
        CRYPT_CIP_REMOTECLIENT => Some(our_external_ip.unwrap_or(Ipv4Addr::UNSPECIFIED).octets()),
        CRYPT_CIP_NONECLIENT => Some([0, 0, 0, 0]),
        _ => None,
    }
}

/// RSA-verify an inbound secure-ident signature (`CClientCreditsList::VerifyIdent`,
/// `RSASSA_PKCS1v15_SHA` = PKCS#1 v1.5 over SHA-1). The signed message is our own
/// public key followed by the challenge we issued the peer (V1), plus the
/// challenge IP + ip-kind byte when the peer used V2. Returns `true` only on a
/// cryptographically valid signature so the caller can gate credit attribution.
pub(super) fn verify_inbound_signature(
    our_public_key_der: &[u8],
    our_challenge_for: u32,
    peer_public_key: &[u8],
    signature: &SecureIdentSignature,
    peer_ip: Ipv4Addr,
    our_external_ip: Option<Ipv4Addr>,
) -> Result<bool> {
    // eMule refuses to verify without an outstanding challenge (replay guard).
    if our_challenge_for == 0 {
        anyhow::bail!("cannot verify secure-ident signature without an issued challenge");
    }
    let public_key = parse_peer_public_key(peer_public_key)?;

    let mut message = Vec::with_capacity(our_public_key_der.len() + 9);
    message.extend_from_slice(our_public_key_der);
    message.extend_from_slice(&our_challenge_for.to_le_bytes());
    if let Some(ip_kind) = signature.challenge_ip_kind {
        let Some(ip_bytes) = challenge_ip_bytes(ip_kind, peer_ip, our_external_ip) else {
            anyhow::bail!("unsupported secure-ident V2 ip-kind {ip_kind}");
        };
        message.extend_from_slice(&ip_bytes);
        message.push(ip_kind);
    }

    let parsed_signature = Signature::try_from(signature.signature.as_slice())
        .context("malformed RSA signature bytes")?;
    let verifying_key = VerifyingKey::<Sha1>::new(public_key);
    Ok(verifying_key.verify(&message, &parsed_signature).is_ok())
}

/// Verify a received `OP_SIGNATURE` against the peer's public key + the challenge
/// we issued, updating the peer secure-ident state. Always records that a
/// signature arrived; sets `peer_ident_verified` only on a cryptographically
/// valid signature (eMule `IS_IDENTIFIED`). Returns whether the peer is now
/// proven, so the caller can gate credit attribution to the peer's user hash.
pub(super) fn verify_peer_secure_ident_signature(
    secure_ident: &Ed2kSecureIdent,
    peer_state: &mut Ed2kPeerSecureIdentState,
    signature: &SecureIdentSignature,
    peer_addr: SocketAddr,
    our_external_ip: Option<Ipv4Addr>,
) -> bool {
    peer_state.peer_signature_received = true;
    peer_state.peer_ident_verified = false;

    let Some(peer_public_key) = peer_state.peer_public_key.as_deref() else {
        return false; // no key to verify against (eMule drops these)
    };
    let Some(challenge) = peer_state.challenge_for else {
        return false; // we never issued a challenge (replay guard)
    };
    let SocketAddr::V4(peer_v4) = peer_addr else {
        return false; // IPv4-only client
    };

    match verify_inbound_signature(
        secure_ident.public_key_der(),
        challenge,
        peer_public_key,
        signature,
        *peer_v4.ip(),
        our_external_ip,
    ) {
        Ok(true) => {
            peer_state.peer_ident_verified = true;
            true
        }
        Ok(false) | Err(_) => false,
    }
}

pub(super) fn random_nonzero_u32() -> u32 {
    loop {
        let value: u32 = rand::random();
        if value != 0 {
            return value;
        }
    }
}

pub(super) fn begin_secure_ident_probe(peer_state: &mut Ed2kPeerSecureIdentState) -> Vec<u8> {
    let challenge_for = random_nonzero_u32();
    peer_state.challenge_for = Some(challenge_for);
    peer_state.requested_peer_key = true;
    encode_secident_state(ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, challenge_for)
}

pub(super) async fn try_send_secure_ident_signature(
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    secure_ident: &Ed2kSecureIdent,
    peer_state: &mut Ed2kPeerSecureIdentState,
) -> Result<bool> {
    let Some(peer_public_key) = peer_state.peer_public_key.as_deref() else {
        return Ok(false);
    };
    let Some(challenge) = peer_state.peer_challenge_from else {
        return Ok(false);
    };
    if !peer_state.pending_signature {
        return Ok(false);
    }
    let signature = encode_packet(
        OP_EMULEPROT,
        OP_SIGNATURE,
        &secure_ident.signature_payload(peer_public_key, challenge)?,
    );
    transport
        .write_all(&signature)
        .await
        .with_context(|| format!("failed to send OP_SIGNATURE to {peer_addr}"))?;
    peer_state.pending_signature = false;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident() -> Ed2kSecureIdent {
        Ed2kSecureIdent::generate().expect("keypair")
    }

    /// A peer signs `our_pubkey ‖ challenge` (+ optional V2 ip-kind trailer) with
    /// its own RSA key, exactly as `CClientCreditsList::CreateSignature` does.
    fn peer_sign(
        peer: &Ed2kSecureIdent,
        our_public_key_der: &[u8],
        challenge: u32,
        v2: Option<(u8, [u8; 4])>,
    ) -> SecureIdentSignature {
        use rsa::signature::SignatureEncoding;
        let mut message = Vec::new();
        message.extend_from_slice(our_public_key_der);
        message.extend_from_slice(&challenge.to_le_bytes());
        if let Some((ip_kind, ip)) = v2 {
            message.extend_from_slice(&ip);
            message.push(ip_kind);
        }
        let signing_key = SigningKey::<Sha1>::new(peer.private_key.clone());
        let bytes = signing_key.sign_with_rng(&mut OsRng, &message).to_bytes();
        SecureIdentSignature {
            signature_len: bytes.len() as u8,
            challenge_ip_kind: v2.map(|(kind, _)| kind),
            signature: bytes.to_vec(),
        }
    }

    #[test]
    fn v1_valid_signature_verifies() {
        let us = ident();
        let peer = ident();
        let challenge = 0xDEAD_BEEF;
        let sig = peer_sign(&peer, us.public_key_der(), challenge, None);
        let ok = verify_inbound_signature(
            us.public_key_der(),
            challenge,
            peer.public_key_der(),
            &sig,
            Ipv4Addr::new(198, 51, 100, 7),
            None,
        )
        .expect("verify ran");
        assert!(ok, "a valid V1 signature must verify");
    }

    #[test]
    fn tampered_signature_fails() {
        let us = ident();
        let peer = ident();
        let challenge = 0x0102_0304;
        let mut sig = peer_sign(&peer, us.public_key_der(), challenge, None);
        sig.signature[5] ^= 0xFF; // flip a byte
        let ok = verify_inbound_signature(
            us.public_key_der(),
            challenge,
            peer.public_key_der(),
            &sig,
            Ipv4Addr::new(198, 51, 100, 7),
            None,
        )
        .expect("verify ran");
        assert!(!ok, "a tampered signature must not verify");
    }

    #[test]
    fn wrong_challenge_fails() {
        let us = ident();
        let peer = ident();
        let sig = peer_sign(&peer, us.public_key_der(), 0xAAAA_AAAA, None);
        // Verify with a different challenge than the one the peer signed over.
        let ok = verify_inbound_signature(
            us.public_key_der(),
            0xBBBB_BBBB,
            peer.public_key_der(),
            &sig,
            Ipv4Addr::new(198, 51, 100, 7),
            None,
        )
        .expect("verify ran");
        assert!(!ok, "a signature over a different challenge must not verify");
    }

    #[test]
    fn wrong_signer_key_fails() {
        let us = ident();
        let peer = ident();
        let impostor = ident();
        let challenge = 0x1111_2222;
        let sig = peer_sign(&peer, us.public_key_der(), challenge, None);
        // Verify the peer's signature against an impostor's public key.
        let ok = verify_inbound_signature(
            us.public_key_der(),
            challenge,
            impostor.public_key_der(),
            &sig,
            Ipv4Addr::new(198, 51, 100, 7),
            None,
        )
        .expect("verify ran");
        assert!(!ok, "a signature must not verify under a different key");
    }

    #[test]
    fn v2_localclient_signature_binds_peer_ip() {
        let us = ident();
        let peer = ident();
        let challenge = 0x3333_4444;
        let peer_ip = Ipv4Addr::new(203, 0, 113, 42);
        let sig = peer_sign(
            &peer,
            us.public_key_der(),
            challenge,
            Some((CRYPT_CIP_LOCALCLIENT, peer_ip.octets())),
        );
        assert!(
            verify_inbound_signature(
                us.public_key_der(),
                challenge,
                peer.public_key_der(),
                &sig,
                peer_ip,
                None,
            )
            .expect("verify ran"),
            "V2 LOCALCLIENT verifies against the peer IP"
        );
        // Same signature replayed against a different endpoint IP must fail.
        assert!(
            !verify_inbound_signature(
                us.public_key_der(),
                challenge,
                peer.public_key_der(),
                &sig,
                Ipv4Addr::new(203, 0, 113, 99),
                None,
            )
            .expect("verify ran"),
            "V2 LOCALCLIENT must not verify when replayed to another IP"
        );
    }

    #[test]
    fn verify_without_issued_challenge_errors() {
        let us = ident();
        let peer = ident();
        let sig = peer_sign(&peer, us.public_key_der(), 1, None);
        assert!(
            verify_inbound_signature(
                us.public_key_der(),
                0, // no challenge issued
                peer.public_key_der(),
                &sig,
                Ipv4Addr::new(198, 51, 100, 7),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn helper_sets_verified_only_on_valid_signature() {
        let us = ident();
        let peer = ident();
        let challenge = 0x5555_6666;
        let peer_addr: SocketAddr = "198.51.100.7:4662".parse().unwrap();

        let mut state = Ed2kPeerSecureIdentState {
            peer_public_key: Some(peer.public_key_der().to_vec()),
            challenge_for: Some(challenge),
            ..Default::default()
        };
        let good = peer_sign(&peer, us.public_key_der(), challenge, None);
        assert!(verify_peer_secure_ident_signature(
            &us, &mut state, &good, peer_addr, None
        ));
        assert!(state.peer_ident_verified);
        assert!(state.peer_signature_received);

        // A subsequent tampered signature clears the verified flag.
        let mut bad = good.clone();
        bad.signature[3] ^= 0xFF;
        assert!(!verify_peer_secure_ident_signature(
            &us, &mut state, &bad, peer_addr, None
        ));
        assert!(!state.peer_ident_verified);
        assert!(state.peer_signature_received);
    }
}
