use std::net::SocketAddr;

use anyhow::Result;
use md5::compute as md5_compute;
use rand::RngExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::debug;

use super::{
    EMULE_CRYPT_REQUESTS, EMULE_CRYPT_REQUIRES, EMULE_CRYPT_SUPPORTS,
    EMULE_ENCRYPTION_METHOD_OBFUSCATION, EMULE_TCP_CRYPT_DISCARD_LEN,
    EMULE_TCP_CRYPT_MAGIC_REQUESTER, EMULE_TCP_CRYPT_MAGIC_SERVER, EMULE_TCP_CRYPT_MAGIC_SYNC,
    OP_EDONKEYPROT, OP_EMULEPROT, OP_PACKEDPROT,
};

#[derive(Debug)]
pub(super) struct Rc4KeyStream {
    s: [u8; 256],
    i: usize,
    j: usize,
}

impl Rc4KeyStream {
    fn new(key: &[u8]) -> Self {
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
        let mut discard = [0u8; EMULE_TCP_CRYPT_DISCARD_LEN];
        stream.apply(&mut discard);
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

pub(super) fn is_plain_ed2k_protocol_marker(marker: u8) -> bool {
    matches!(marker, OP_EDONKEYPROT | OP_PACKEDPROT | OP_EMULEPROT)
}

pub(super) fn derive_obfuscation_key(
    user_hash: [u8; 16],
    magic: u8,
    random_key_part: [u8; 4],
) -> Rc4KeyStream {
    let mut key_material = [0u8; 21];
    key_material[..16].copy_from_slice(&user_hash);
    key_material[16] = magic;
    key_material[17..].copy_from_slice(&random_key_part);
    Rc4KeyStream::new(&md5_compute(key_material).0)
}

pub(super) fn should_enable_outgoing_obfuscation(
    local_connect_options: u8,
    peer_user_hash: Option<[u8; 16]>,
    peer_connect_options: Option<u8>,
) -> Result<bool> {
    let Some(connect_options) = peer_connect_options else {
        return Ok(false);
    };
    let local_supports_crypt_layer = local_connect_options & EMULE_CRYPT_SUPPORTS != 0;
    let supports_crypt_layer = connect_options & EMULE_CRYPT_SUPPORTS != 0;
    let requests_crypt_layer = connect_options & EMULE_CRYPT_REQUESTS != 0;
    let requires_crypt_layer = connect_options & EMULE_CRYPT_REQUIRES != 0;

    if requires_crypt_layer && !local_supports_crypt_layer {
        anyhow::bail!("peer requires eD2k TCP obfuscation but local obfuscation is disabled");
    }

    if requires_crypt_layer && (!supports_crypt_layer || peer_user_hash.is_none()) {
        anyhow::bail!(
            "peer requires eD2k TCP obfuscation without advertising usable support metadata"
        );
    }

    Ok(local_supports_crypt_layer
        && supports_crypt_layer
        && peer_user_hash.is_some()
        && (requests_crypt_layer || local_connect_options & EMULE_CRYPT_REQUESTS != 0))
}

fn random_non_protocol_marker() -> u8 {
    loop {
        let marker = rand::random::<u8>();
        if !is_plain_ed2k_protocol_marker(marker) {
            return marker;
        }
    }
}

pub(super) async fn negotiate_outgoing_obfuscation_handshake(
    stream: &mut TcpStream,
    peer_user_hash: [u8; 16],
    flow: &'static str,
    peer_addr: SocketAddr,
) -> Result<(Rc4KeyStream, Rc4KeyStream)> {
    let random_key_part = rand::random::<u32>().to_le_bytes();
    let mut send_cipher = derive_obfuscation_key(
        peer_user_hash,
        EMULE_TCP_CRYPT_MAGIC_REQUESTER,
        random_key_part,
    );
    let mut receive_cipher = derive_obfuscation_key(
        peer_user_hash,
        EMULE_TCP_CRYPT_MAGIC_SERVER,
        random_key_part,
    );

    // eMule CryptTCPPaddingLength default profile (Preferences.cpp:3527 = 128,
    // capped 254); EncryptedStreamSocket.cpp:422 pads rand % (len+1) -> 0..=128.
    let request_padding_len = rand::rng().random_range(0..=128usize);
    let mut request = Vec::with_capacity(12 + request_padding_len);
    request.push(random_non_protocol_marker());
    request.extend_from_slice(&random_key_part);

    let mut clear_tail = Vec::with_capacity(7 + request_padding_len);
    clear_tail.extend_from_slice(&EMULE_TCP_CRYPT_MAGIC_SYNC.to_le_bytes());
    clear_tail.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
    clear_tail.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
    clear_tail.push(u8::try_from(request_padding_len).expect("padding length fits in u8"));
    let mut request_padding = vec![0u8; request_padding_len];
    rand::rng().fill(&mut request_padding[..]);
    clear_tail.extend_from_slice(&request_padding);
    let mut encrypted_tail = clear_tail.clone();
    send_cipher.apply(&mut encrypted_tail);
    request.extend_from_slice(&encrypted_tail);
    let mut clear_request = request[..5].to_vec();
    clear_request.extend_from_slice(&clear_tail);
    stream.write_all(&request).await?;
    super::dump::dump_ed2k_tcp_handshake_step(
        flow,
        peer_addr,
        "obfuscation_request",
        "send",
        "send_succeeded",
        &request,
        &clear_request,
    );

    let mut encrypted_header = [0u8; 6];
    stream.read_exact(&mut encrypted_header).await?;
    let mut raw_response = encrypted_header.to_vec();
    receive_cipher.apply(&mut encrypted_header);
    let mut clear_response = encrypted_header.to_vec();
    let magic = u32::from_le_bytes(encrypted_header[..4].try_into().unwrap());
    if magic != EMULE_TCP_CRYPT_MAGIC_SYNC {
        anyhow::bail!("invalid obfuscated eD2k TCP response magic 0x{magic:08X}");
    }
    if encrypted_header[4] != EMULE_ENCRYPTION_METHOD_OBFUSCATION {
        anyhow::bail!(
            "peer selected unsupported eD2k TCP encryption method 0x{:02X}",
            encrypted_header[4]
        );
    }
    let padding_len = usize::from(encrypted_header[5]);
    if padding_len > 0 {
        let mut encrypted_padding = vec![0u8; padding_len];
        stream.read_exact(&mut encrypted_padding).await?;
        raw_response.extend_from_slice(&encrypted_padding);
        receive_cipher.apply(&mut encrypted_padding);
        clear_response.extend_from_slice(&encrypted_padding);
    }
    super::dump::dump_ed2k_tcp_handshake_step(
        flow,
        peer_addr,
        "obfuscation_response",
        "recv",
        "accepted",
        &raw_response,
        &clear_response,
    );
    Ok((receive_cipher, send_cipher))
}

fn decrypt_incoming_obfuscation_header(
    receive_cipher: &mut Rc4KeyStream,
    encrypted_header: [u8; 7],
) -> Result<([u8; 7], usize, u8, u8)> {
    let mut decrypted = encrypted_header;
    receive_cipher.apply(&mut decrypted);
    let magic = u32::from_le_bytes(decrypted[..4].try_into().unwrap());
    if magic != EMULE_TCP_CRYPT_MAGIC_SYNC {
        anyhow::bail!("invalid obfuscated eD2k TCP magic 0x{magic:08X}");
    }
    Ok((
        decrypted,
        usize::from(decrypted[6]),
        decrypted[4],
        decrypted[5],
    ))
}

pub(super) fn decode_incoming_obfuscation_header(
    receive_cipher: &mut Rc4KeyStream,
    encrypted_header: [u8; 7],
) -> Result<(usize, u8, u8)> {
    let (_, padding_len, supported_methods, requested_method) =
        decrypt_incoming_obfuscation_header(receive_cipher, encrypted_header)?;
    Ok((padding_len, supported_methods, requested_method))
}

pub(super) fn encode_incoming_obfuscation_response(
    send_cipher: &mut Rc4KeyStream,
    padding: &[u8],
) -> Vec<u8> {
    let mut response = Vec::with_capacity(6 + padding.len());
    response.extend_from_slice(&EMULE_TCP_CRYPT_MAGIC_SYNC.to_le_bytes());
    response.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
    response.push(u8::try_from(padding.len()).expect("padding length fits in u8"));
    response.extend_from_slice(padding);
    send_cipher.apply(&mut response);
    response
}

pub(super) async fn accept_incoming_obfuscation_handshake(
    stream: &mut TcpStream,
    local_user_hash: [u8; 16],
    first_marker: u8,
    flow: &'static str,
    peer_addr: SocketAddr,
) -> Result<(Rc4KeyStream, Rc4KeyStream)> {
    if is_plain_ed2k_protocol_marker(first_marker) {
        anyhow::bail!("plaintext marker 0x{first_marker:02X} cannot start obfuscated handshake");
    }

    let mut random_key_part = [0u8; 4];
    stream.read_exact(&mut random_key_part).await?;
    let mut raw_request = Vec::with_capacity(12);
    raw_request.push(first_marker);
    raw_request.extend_from_slice(&random_key_part);
    let mut clear_request = raw_request.clone();
    let mut receive_cipher = derive_obfuscation_key(
        local_user_hash,
        EMULE_TCP_CRYPT_MAGIC_REQUESTER,
        random_key_part,
    );
    let mut send_cipher = derive_obfuscation_key(
        local_user_hash,
        EMULE_TCP_CRYPT_MAGIC_SERVER,
        random_key_part,
    );

    let mut encrypted_header = [0u8; 7];
    stream.read_exact(&mut encrypted_header).await?;
    raw_request.extend_from_slice(&encrypted_header);
    let (decrypted_header, padding_len, supported_methods, requested_method) =
        decrypt_incoming_obfuscation_header(&mut receive_cipher, encrypted_header)?;
    clear_request.extend_from_slice(&decrypted_header);
    if requested_method != EMULE_ENCRYPTION_METHOD_OBFUSCATION {
        debug!(
            "peer requested unsupported eD2k TCP encryption method 0x{requested_method:02X}; falling back to obfuscation"
        );
    }
    if supported_methods != EMULE_ENCRYPTION_METHOD_OBFUSCATION {
        debug!(
            "peer advertised unexpected eD2k TCP encryption support mask 0x{supported_methods:02X}"
        );
    }

    if padding_len > 0 {
        let mut ignored_padding = vec![0u8; padding_len];
        stream.read_exact(&mut ignored_padding).await?;
        raw_request.extend_from_slice(&ignored_padding);
        receive_cipher.apply(&mut ignored_padding);
        clear_request.extend_from_slice(&ignored_padding);
    }
    super::dump::dump_ed2k_tcp_handshake_step(
        flow,
        peer_addr,
        "obfuscation_request",
        "recv",
        "accepted",
        &raw_request,
        &clear_request,
    );

    // Same stock CryptTCPPaddingLength=128 default profile as the request side.
    let response_padding_len = rand::rng().random_range(0..=128usize);
    let mut response_padding = vec![0u8; response_padding_len];
    rand::rng().fill(&mut response_padding[..]);
    let mut clear_response = Vec::with_capacity(6 + response_padding.len());
    clear_response.extend_from_slice(&EMULE_TCP_CRYPT_MAGIC_SYNC.to_le_bytes());
    clear_response.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
    clear_response.push(u8::try_from(response_padding.len()).expect("padding length fits in u8"));
    clear_response.extend_from_slice(&response_padding);
    let response = encode_incoming_obfuscation_response(&mut send_cipher, &response_padding);
    stream.write_all(&response).await?;
    super::dump::dump_ed2k_tcp_handshake_step(
        flow,
        peer_addr,
        "obfuscation_response",
        "send",
        "send_succeeded",
        &response,
        &clear_response,
    );
    Ok((receive_cipher, send_cipher))
}
