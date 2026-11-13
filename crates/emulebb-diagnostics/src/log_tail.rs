//! Bounded complete-record JSONL reads shared by diagnostic exporters.

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

pub struct JsonlTail {
    pub file_size: u64,
    pub tail_start_offset: u64,
    pub bytes_read: usize,
    pub incomplete_final_line_ignored: bool,
    pub lines: Vec<Vec<u8>>,
}

/// Read at most `max_bytes`, excluding a partial leading record and optionally
/// an active writer's incomplete final record. The caller owns the byte budget.
pub fn read_jsonl_tail(
    path: &Path,
    max_bytes: u64,
    ignore_incomplete_final_line: bool,
) -> io::Result<JsonlTail> {
    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();
    let bytes_to_read = file_size.min(max_bytes);
    let tail_start_offset = file_size.saturating_sub(bytes_to_read);
    file.seek(SeekFrom::Start(tail_start_offset))?;
    let capacity = usize::try_from(bytes_to_read).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "JSONL tail budget exceeds addressable memory",
        )
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(bytes_to_read).read_to_end(&mut bytes)?;
    let bytes_read = bytes.len();
    if tail_start_offset > 0 {
        if let Some(newline) = bytes.iter().position(|byte| *byte == b'\n') {
            bytes.drain(..=newline);
        } else {
            bytes.clear();
        }
    }
    let incomplete_final_line_ignored =
        ignore_incomplete_final_line && bytes.last().is_some_and(|last| *last != b'\n');
    if incomplete_final_line_ignored {
        if let Some(newline) = bytes.iter().rposition(|byte| *byte == b'\n') {
            bytes.truncate(newline + 1);
        } else {
            bytes.clear();
        }
    }
    let lines = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(<[u8]>::to_vec)
        .collect();
    Ok(JsonlTail {
        file_size,
        tail_start_offset,
        bytes_read,
        incomplete_final_line_ignored,
        lines,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_tail_excludes_partial_leading_and_active_final_records() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("sample.jsonl");
        std::fs::write(&path, b"old-record\ncomplete\nunfinished").unwrap();
        let tail = read_jsonl_tail(&path, 25, true).unwrap();
        assert!(tail.bytes_read <= 25);
        assert!(tail.tail_start_offset > 0);
        assert!(tail.incomplete_final_line_ignored);
        assert_eq!(tail.lines, vec![b"complete".to_vec()]);
    }
}
