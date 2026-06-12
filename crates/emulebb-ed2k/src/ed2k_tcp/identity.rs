use std::{fs, net::SocketAddr, path::Path};

use anyhow::{Context, Result};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1v15::SigningKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
    rand_core::OsRng,
    signature::{RandomizedSigner, SignatureEncoding},
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SecureIdentSignature {
    pub(super) signature_len: u8,
    pub(super) challenge_ip_kind: Option<u8>,
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
    Ok(SecureIdentSignature {
        signature_len,
        challenge_ip_kind,
    })
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
