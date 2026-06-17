use anyhow::{Context, Result};

use super::{OP_EMULEPROT, OP_FILEDESC, encode_packet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::ed2k_tcp) struct FileDescription {
    pub(in crate::ed2k_tcp) rating: u8,
    pub(in crate::ed2k_tcp) comment: String,
}

fn encode_file_description_body(rating: u8, comment: &str) -> Vec<u8> {
    let comment_bytes = comment.as_bytes();
    let mut body = Vec::with_capacity(1 + 4 + comment_bytes.len());
    body.push(rating);
    body.extend_from_slice(
        &u32::try_from(comment_bytes.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    body.extend_from_slice(comment_bytes);
    body
}

pub(in crate::ed2k_tcp) fn encode_file_desc(rating: u8, comment: &str) -> Vec<u8> {
    encode_packet(
        OP_EMULEPROT,
        OP_FILEDESC,
        &encode_file_description_body(rating, comment),
    )
}

pub(in crate::ed2k_tcp) fn decode_file_description_payload(
    payload: &[u8],
) -> Result<FileDescription> {
    if payload.len() < 5 {
        anyhow::bail!("short OP_FILEDESC payload {}", payload.len());
    }
    let rating = payload[0];
    let comment_len = usize::try_from(u32::from_le_bytes(payload[1..5].try_into().unwrap()))
        .context("OP_FILEDESC comment length overflow")?;
    if payload.len() < 5 + comment_len {
        anyhow::bail!(
            "short OP_FILEDESC comment {} expected {}",
            payload.len() - 5,
            comment_len
        );
    }
    let comment = String::from_utf8_lossy(&payload[5..5 + comment_len]).into_owned();
    Ok(FileDescription { rating, comment })
}
