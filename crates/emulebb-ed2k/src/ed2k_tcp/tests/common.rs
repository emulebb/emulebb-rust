use super::*;

pub(super) fn test_bind_ip() -> Ipv4Addr {
    crate::test_bind_ip()
}

pub(super) fn test_bind_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(test_bind_ip()), 0)
}

pub(super) async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
    try_read_packet(stream).await.unwrap()
}

pub(super) async fn try_read_packet(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 6];
    stream.read_exact(&mut header).await?;
    let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
    let mut packet = header.to_vec();
    let mut payload = vec![0u8; packet_len - 1];
    stream.read_exact(&mut payload).await?;
    packet.extend_from_slice(&payload);
    Ok(packet)
}

pub(super) async fn read_until_opcode(stream: &mut TcpStream, protocol: u8, opcode: u8) -> Vec<u8> {
    loop {
        let packet = read_packet(stream).await;
        if packet[0] == protocol && packet[5] == opcode {
            return packet;
        }
    }
}
