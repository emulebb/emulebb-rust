use anyhow::Result;
use md5::compute as md5_compute;
use num_bigint::BigUint;
use rand::RngCore;

use super::{
    EMULE_TCP_CRYPT_DISCARD_LEN, OP_EDONKEYPROT, OP_EMULEPROT, OP_PACKEDPROT, ResolvedServerEntry,
};

#[derive(Debug)]
pub(super) struct Rc4KeyStream {
    s: [u8; 256],
    i: usize,
    j: usize,
}

impl Rc4KeyStream {
    fn new(key: &[u8]) -> Self {
        Self::new_with_discard(key, EMULE_TCP_CRYPT_DISCARD_LEN)
    }

    pub(super) fn new_without_discard(key: &[u8]) -> Self {
        Self::new_with_discard(key, 0)
    }

    fn new_with_discard(key: &[u8], discard_len: usize) -> Self {
        let mut s = [0u8; 256];
        for (index, value) in s.iter_mut().enumerate() {
            *value = index as u8;
        }
        let mut j = 0usize;
        for i in 0..256usize {
            j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xFF;
            s.swap(i, j);
        }
        let mut stream = Self { s, i: 0, j: 0 };
        for _ in 0..discard_len {
            let mut discard = [0u8; 1];
            stream.apply(&mut discard);
        }
        stream
    }

    pub(super) fn apply(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            self.i = (self.i + 1) & 0xFF;
            self.j = (self.j + self.s[self.i] as usize) & 0xFF;
            self.s.swap(self.i, self.j);
            *byte ^= self.s[(self.s[self.i] as usize + self.s[self.j] as usize) & 0xFF];
        }
    }
}

/// Returns whether the Rust client should start an ED2K server session with TCP
/// obfuscation.
///
/// Stock eMule/eMuleBB tries an obfuscated server TCP connect when the server
/// advertises support, and also once for metadata-poor servers which have not
/// been probed yet. Endpoint-only Rust configs are metadata-poor, so the first
/// transport choice should be obfuscated when local crypt is enabled.
pub(super) fn should_use_server_obfuscation(
    connect_options: u8,
    server: &ResolvedServerEntry,
) -> bool {
    connect_options != 0
        && (server.entry.supports_obfuscation_tcp() || !server.entry.has_obfuscation_metadata())
}

pub(super) fn random_nonzero_biguint(byte_len: usize) -> BigUint {
    let mut bytes = vec![0u8; byte_len];
    rand::thread_rng().fill_bytes(&mut bytes);
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[byte_len - 1] = 1;
    }
    BigUint::from_bytes_be(&bytes)
}

pub(super) fn biguint_to_fixed_be(value: &BigUint, byte_len: usize) -> Result<Vec<u8>> {
    let bytes = value.to_bytes_be();
    if bytes.len() > byte_len {
        anyhow::bail!(
            "big integer requires {} bytes, expected at most {}",
            bytes.len(),
            byte_len
        );
    }
    let mut fixed = vec![0u8; byte_len];
    fixed[byte_len - bytes.len()..].copy_from_slice(&bytes);
    Ok(fixed)
}

pub(super) fn derive_server_cipher(shared_secret: &[u8], magic: u8) -> Rc4KeyStream {
    let mut key_material = Vec::with_capacity(shared_secret.len() + 1);
    key_material.extend_from_slice(shared_secret);
    key_material.push(magic);
    Rc4KeyStream::new(&md5_compute(key_material).0)
}

pub(super) fn random_non_protocol_marker() -> u8 {
    loop {
        let mut marker = [0u8; 1];
        rand::thread_rng().fill_bytes(&mut marker);
        let marker = marker[0];
        if !matches!(marker, OP_EDONKEYPROT | OP_EMULEPROT | OP_PACKEDPROT) {
            return marker;
        }
    }
}
