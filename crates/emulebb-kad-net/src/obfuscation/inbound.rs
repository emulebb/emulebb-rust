use crate::obfuscation::crypto::{derive_kad_receiver_key, derive_kad_request_key, rc4};
use crate::obfuscation::{
    DecryptResult, KAD_MARKER_RECEIVER_KEY, KadKeyMode, MAGICVALUE_UDP_SYNC_CLIENT,
    ObfuscationLayer,
};
use emulebb_kad_proto::constants::{OP_KADEMLIAHEADER, OP_KADEMLIAPACKEDPROT};
use std::net::{IpAddr, SocketAddr};

fn plaintext_result(buf: &[u8]) -> DecryptResult {
    DecryptResult {
        data: buf.to_vec(),
        was_obfuscated: false,
        sender_verify_key: None,
        receiver_verify_key_valid: false,
    }
}

fn marker_try_order(marker: u8) -> [KadKeyMode; 2] {
    match marker & 0x03 {
        KAD_MARKER_RECEIVER_KEY => [KadKeyMode::ReceiverVerifyKey, KadKeyMode::NodeId],
        _ => [KadKeyMode::NodeId, KadKeyMode::ReceiverVerifyKey],
    }
}

impl ObfuscationLayer {
    /// Attempt to decrypt an incoming Kad packet.
    pub fn decrypt(&self, from: SocketAddr, buf: &[u8]) -> DecryptResult {
        if buf.len() < 3 {
            return plaintext_result(buf);
        }

        if matches!(buf[0], OP_KADEMLIAHEADER | OP_KADEMLIAPACKEDPROT) {
            return plaintext_result(buf);
        }

        let random_key_part = u16::from_le_bytes([buf[1], buf[2]]);
        let remote_ip = match from.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => {
                return plaintext_result(buf);
            }
        };

        for mode in marker_try_order(buf[0]) {
            let rc4_key = match mode {
                KadKeyMode::NodeId => derive_kad_request_key(self.our_node_id, random_key_part),
                KadKeyMode::ReceiverVerifyKey => {
                    derive_kad_receiver_key(self.verify_key_for_ip(remote_ip), random_key_part)
                }
            };

            let mut decrypted = buf[3..].to_vec();
            rc4(&rc4_key, &mut decrypted);
            if decrypted.len() < 13 {
                continue;
            }

            let magic = u32::from_le_bytes(decrypted[0..4].try_into().unwrap());
            if magic != MAGICVALUE_UDP_SYNC_CLIENT {
                continue;
            }

            let padding_len = usize::from(decrypted[4] & 0x0F);
            let payload_offset = 5 + padding_len + 8;
            if decrypted.len() <= payload_offset {
                continue;
            }

            let sender_verify_key = u32::from_le_bytes(
                decrypted[5 + padding_len + 4..5 + padding_len + 8]
                    .try_into()
                    .unwrap(),
            );
            let payload = decrypted.split_off(payload_offset);
            if payload.first().copied() != Some(OP_KADEMLIAHEADER)
                && payload.first().copied() != Some(OP_KADEMLIAPACKEDPROT)
            {
                continue;
            }

            return DecryptResult {
                data: payload,
                was_obfuscated: true,
                sender_verify_key: Some(sender_verify_key),
                receiver_verify_key_valid: matches!(mode, KadKeyMode::ReceiverVerifyKey),
            };
        }

        plaintext_result(buf)
    }
}
