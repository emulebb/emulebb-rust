use crate::obfuscation::ObfuscationLayer;
use emulebb_kad_proto::NodeId;
use md5::compute as md5_compute;
use std::net::Ipv4Addr;

pub(super) fn rc4(key: &[u8], data: &mut [u8]) {
    if key.is_empty() || data.is_empty() {
        return;
    }
    let klen = key.len();
    let mut s = [0u8; 256];
    for (i, value) in s.iter_mut().enumerate() {
        *value = i as u8;
    }
    let mut j = 0usize;
    for i in 0..256usize {
        j = (j + s[i] as usize + key[i % klen] as usize) & 0xFF;
        s.swap(i, j);
    }
    let mut i = 0usize;
    let mut j = 0usize;
    for byte in data.iter_mut() {
        i = (i + 1) & 0xFF;
        j = (j + s[i] as usize) & 0xFF;
        s.swap(i, j);
        *byte ^= s[(s[i] as usize + s[j] as usize) & 0xFF];
    }
}

pub(super) fn md5_key_material(bytes: &[u8]) -> [u8; 16] {
    md5_compute(bytes).0
}

pub(super) fn derive_kad_request_key(node_id: NodeId, random_key_part: u16) -> [u8; 16] {
    let mut key_data = [0u8; 18];
    key_data[..16].copy_from_slice(&node_id.0);
    key_data[16..18].copy_from_slice(&random_key_part.to_le_bytes());
    md5_key_material(&key_data)
}

pub(super) fn derive_kad_receiver_key(receiver_verify_key: u32, random_key_part: u16) -> [u8; 16] {
    let mut key_data = [0u8; 6];
    key_data[..4].copy_from_slice(&receiver_verify_key.to_le_bytes());
    key_data[4..6].copy_from_slice(&random_key_part.to_le_bytes());
    md5_key_material(&key_data)
}

pub(super) fn derive_udp_verify_key(our_udp_key: u32, target_ip: Ipv4Addr) -> u32 {
    // eMule hashes the native in-memory bytes of:
    //   (<our Kad UDP key> << 32) | sockAddr.sin_addr.s_addr
    // On little-endian Windows, `sin_addr.s_addr` is already stored with the
    // IPv4 octets in network order in memory, so the hashed 8-byte buffer is:
    //   <ipv4 octets as seen on the wire><our_udp_key little-endian>
    let mut key_data = [0u8; 8];
    key_data[..4].copy_from_slice(&target_ip.octets());
    key_data[4..8].copy_from_slice(&our_udp_key.to_le_bytes());
    let digest = md5_key_material(&key_data);
    let folded = u32::from_le_bytes(digest[0..4].try_into().unwrap())
        ^ u32::from_le_bytes(digest[4..8].try_into().unwrap())
        ^ u32::from_le_bytes(digest[8..12].try_into().unwrap())
        ^ u32::from_le_bytes(digest[12..16].try_into().unwrap());
    (folded % 0xFFFF_FFFE) + 1
}

impl ObfuscationLayer {
    /// Derive the verify key we would announce to a specific IPv4 peer.
    pub fn verify_key_for_ip(&self, ip: Ipv4Addr) -> u32 {
        derive_udp_verify_key(self.our_udp_key, ip)
    }
}
