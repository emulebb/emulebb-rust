use super::*;

#[test]
fn incoming_obfuscation_handshake_roundtrip_encrypts_followup_packets() {
    let user_hash = [0x44; 16];
    let random_key_part = [0x11, 0x22, 0x33, 0x44];
    let client_padding = [0xAA, 0xBB, 0xCC];
    let server_padding = [0x10, 0x20];

    let mut client_send =
        derive_obfuscation_key(user_hash, EMULE_TCP_CRYPT_MAGIC_REQUESTER, random_key_part);
    let mut client_receive =
        derive_obfuscation_key(user_hash, EMULE_TCP_CRYPT_MAGIC_SERVER, random_key_part);

    let mut encrypted_request_tail = Vec::new();
    encrypted_request_tail.extend_from_slice(&EMULE_TCP_CRYPT_MAGIC_SYNC.to_le_bytes());
    encrypted_request_tail.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
    encrypted_request_tail.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
    encrypted_request_tail.push(client_padding.len() as u8);
    encrypted_request_tail.extend_from_slice(&client_padding);
    client_send.apply(&mut encrypted_request_tail);

    let mut incoming_header = [0u8; 7];
    incoming_header.copy_from_slice(&encrypted_request_tail[..7]);
    let mut server_receive =
        derive_obfuscation_key(user_hash, EMULE_TCP_CRYPT_MAGIC_REQUESTER, random_key_part);
    let (padding_len, supported_methods, requested_method) =
        decode_incoming_obfuscation_header(&mut server_receive, incoming_header).unwrap();
    assert_eq!(padding_len, client_padding.len());
    assert_eq!(supported_methods, EMULE_ENCRYPTION_METHOD_OBFUSCATION);
    assert_eq!(requested_method, EMULE_ENCRYPTION_METHOD_OBFUSCATION);

    let mut incoming_padding = encrypted_request_tail[7..].to_vec();
    server_receive.apply(&mut incoming_padding);
    assert_eq!(incoming_padding, client_padding);

    let mut server_send =
        derive_obfuscation_key(user_hash, EMULE_TCP_CRYPT_MAGIC_SERVER, random_key_part);
    let encrypted_response =
        encode_incoming_obfuscation_response(&mut server_send, &server_padding);

    let mut decrypted_response = encrypted_response.clone();
    client_receive.apply(&mut decrypted_response);
    assert_eq!(
        u32::from_le_bytes(decrypted_response[..4].try_into().unwrap()),
        EMULE_TCP_CRYPT_MAGIC_SYNC
    );
    assert_eq!(decrypted_response[4], EMULE_ENCRYPTION_METHOD_OBFUSCATION);
    assert_eq!(usize::from(decrypted_response[5]), server_padding.len());
    assert_eq!(&decrypted_response[6..], &server_padding);

    let plaintext_packet = encode_packet(OP_EDONKEYPROT, OP_HELLOANSWER, &[1, 2, 3, 4]);
    let mut encrypted_packet = plaintext_packet.clone();
    client_send.apply(&mut encrypted_packet);
    server_receive.apply(&mut encrypted_packet);
    assert_eq!(encrypted_packet, plaintext_packet);

    let plaintext_reply = encode_packet(OP_EMULEPROT, OP_EMULEINFOANSWER, &[9, 8, 7]);
    let mut encrypted_reply = plaintext_reply.clone();
    server_send.apply(&mut encrypted_reply);
    client_receive.apply(&mut encrypted_reply);
    assert_eq!(encrypted_reply, plaintext_reply);
}
