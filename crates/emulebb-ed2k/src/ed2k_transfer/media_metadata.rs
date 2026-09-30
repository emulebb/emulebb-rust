//! Bounded media-header extraction for stock ED2K publish tags.
//!
//! Media metadata is derived cache data: an unreadable or malformed file must
//! never prevent a share from loading. Common audio formats use Symphonia's
//! bounded reader with cover-art loading disabled; the legacy video/RIFF
//! fallbacks are bounds checked and inspect at most [`MAX_PREFIX_BYTES`] plus
//! tiny trailers.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use symphonia::core::{
    codecs::audio::{
        AudioCodecId,
        well_known::{CODEC_ID_OPUS, CODEC_ID_SPEEX},
    },
    common::Limit,
    formats::{FormatOptions, TrackType, probe::Hint},
    io::MediaSourceStream,
    meta::{MetadataOptions, MetadataRevision, StandardTag},
};

use super::Ed2kMediaMetadata;

const MAX_PREFIX_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TEXT_CHARS: usize = 80;

pub(super) fn extract_media_metadata(path: &Path, display_name: &str) -> Ed2kMediaMetadata {
    let Ok(mut file) = File::open(path) else {
        return Ed2kMediaMetadata::default();
    };
    let Ok(file_size) = file.metadata().map(|metadata| metadata.len()) else {
        return Ed2kMediaMetadata::default();
    };
    let mut prefix = Vec::with_capacity(file_size.min(MAX_PREFIX_BYTES) as usize);
    if file
        .by_ref()
        .take(MAX_PREFIX_BYTES)
        .read_to_end(&mut prefix)
        .is_err()
    {
        return Ed2kMediaMetadata::default();
    }
    let extension = display_name
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default();
    let mut media = extract_symphonia_audio(path, &extension, file_size).unwrap_or_default();
    let legacy = match extension.as_str() {
        "mp3" | "mp2" | "mp1" | "mpa" => extract_mpeg_audio(&mut file, &prefix, file_size),
        "wav" | "avi" => extract_riff(&prefix, file_size),
        "wma" | "wmv" | "asf" => extract_asf(&prefix, &extension),
        "rm" | "rmvb" | "ra" => extract_real_media(&prefix, &extension),
        _ if prefix.starts_with(b"ID3") => extract_mpeg_audio(&mut file, &prefix, file_size),
        _ if prefix.starts_with(b"RIFF") => extract_riff(&prefix, file_size),
        _ => Ed2kMediaMetadata::default(),
    };
    if matches!(
        extension.as_str(),
        "wav" | "avi" | "wma" | "wmv" | "asf" | "rm" | "rmvb" | "ra"
    ) && legacy != Ed2kMediaMetadata::default()
    {
        let mut precise_legacy = legacy;
        merge_missing_media(&mut precise_legacy, media);
        media = precise_legacy;
    } else {
        merge_missing_media(&mut media, legacy);
    }
    if matches!(extension.as_str(), "mp4" | "m4v" | "mov")
        && let Some(codec) = detect_mp4_video_codec(&prefix)
    {
        media.codec = codec.to_string();
    }
    media
}

fn extract_symphonia_audio(
    path: &Path,
    extension: &str,
    file_size: u64,
) -> Option<Ed2kMediaMetadata> {
    if !matches!(
        extension,
        "aac"
            | "aif"
            | "aiff"
            | "ape"
            | "flac"
            | "mp1"
            | "mp2"
            | "mp3"
            | "mpa"
            | "mp4"
            | "m4a"
            | "m4b"
            | "m4v"
            | "mov"
            | "mpc"
            | "oga"
            | "ogg"
            | "opus"
            | "spx"
            | "wav"
            | "wv"
    ) {
        return None;
    }

    let source = MediaSourceStream::new(Box::new(File::open(path).ok()?), Default::default());
    let mut hint = Hint::new();
    hint.with_extension(extension);
    let metadata_options = MetadataOptions::default().limit_visual_bytes(Limit::Maximum(0));
    let mut format = symphonia::default::get_probe()
        .probe(&hint, source, FormatOptions::default(), metadata_options)
        .ok()?;
    let media_info = *format.media_info();
    let (track_id, track_time_base, track_duration, codec) = {
        let track = format.default_track(TrackType::Audio)?;
        let codec = track.codec_params.as_ref()?.audio()?.codec;
        (track.id, track.time_base, track.duration, codec)
    };
    let duration = media_info
        .time_base
        .zip(media_info.duration)
        .and_then(|(time_base, duration)| time_base.calc_duration(duration))
        .or_else(|| {
            track_time_base
                .zip(track_duration)
                .and_then(|(time_base, duration)| time_base.calc_duration(duration))
        });
    let length_seconds = duration
        .map(|duration| u32::try_from(duration.as_secs()).unwrap_or(u32::MAX))
        .unwrap_or_default();
    let mut media = Ed2kMediaMetadata {
        length_seconds,
        bitrate_kbps: duration
            .map(|duration| {
                let seconds = duration.as_secs_f64();
                if seconds > 0.0 {
                    ((file_size as f64 * 8.0 / (seconds * 1_000.0)) + 0.5) as u32
                } else {
                    0
                }
            })
            .unwrap_or_default(),
        codec: symphonia_codec_name(extension, codec).to_string(),
        ..Default::default()
    };

    let mut revisions = Vec::new();
    let mut metadata = format.metadata();
    loop {
        if let Some(revision) = metadata.current() {
            revisions.push(revision.clone());
        }
        if metadata.pop().is_none() {
            break;
        }
    }
    for revision in revisions.iter().rev() {
        merge_symphonia_metadata(&mut media, revision, track_id);
    }
    Some(media)
}

fn merge_symphonia_metadata(
    media: &mut Ed2kMediaMetadata,
    revision: &MetadataRevision,
    track_id: u32,
) {
    let tags = revision.media.tags.iter().chain(
        revision
            .per_track
            .iter()
            .filter(|track| track.track_id == u64::from(track_id))
            .flat_map(|track| track.metadata.tags.iter()),
    );
    for tag in tags {
        let Some(standard) = tag.std.as_ref() else {
            continue;
        };
        let target_and_value = match standard {
            StandardTag::Artist(value) => Some((&mut media.artist, value.as_str())),
            StandardTag::Album(value) => Some((&mut media.album, value.as_str())),
            StandardTag::TrackTitle(value) => Some((&mut media.title, value.as_str())),
            _ => None,
        };
        if let Some((target, value)) = target_and_value
            && target.is_empty()
            && let Some(value) = nonempty_media_text(value)
        {
            *target = value;
        }
    }
}

fn symphonia_codec_name(extension: &str, codec: AudioCodecId) -> &'static str {
    match extension {
        "aac" => "AAC",
        "aif" | "aiff" => "AIFF",
        "ape" => "Monkey's Audio",
        "flac" => "FLAC",
        // Stock's built-in MPEG fallback deliberately omits a codec tag.
        "mp1" | "mp2" | "mp3" | "mpa" => "",
        "mp4" | "m4a" | "m4b" | "m4v" | "mov" => "MPEG-4 Audio",
        "mpc" => "Musepack",
        "opus" => "Opus",
        "spx" => "Speex",
        "oga" | "ogg" if codec == CODEC_ID_OPUS => "Opus",
        "oga" | "ogg" if codec == CODEC_ID_SPEEX => "Speex",
        "oga" | "ogg" => "Vorbis",
        // The RIFF parser below provides the precise WAVE format tag.
        "wav" => "",
        "wv" => "WavPack",
        _ => "",
    }
}

fn merge_missing_media(target: &mut Ed2kMediaMetadata, fallback: Ed2kMediaMetadata) {
    if target.artist.is_empty() {
        target.artist = fallback.artist;
    }
    if target.album.is_empty() {
        target.album = fallback.album;
    }
    if target.title.is_empty() {
        target.title = fallback.title;
    }
    if target.length_seconds == 0 {
        target.length_seconds = fallback.length_seconds;
    }
    if target.bitrate_kbps == 0 {
        target.bitrate_kbps = fallback.bitrate_kbps;
    }
    if target.codec.is_empty() {
        target.codec = fallback.codec;
    }
}

fn detect_mp4_video_codec(bytes: &[u8]) -> Option<&'static str> {
    for (fourcc, label) in [
        (b"avc1".as_slice(), "H.264"),
        (b"avc3".as_slice(), "H.264"),
        (b"hvc1".as_slice(), "H.265"),
        (b"hev1".as_slice(), "H.265"),
        (b"av01".as_slice(), "AV1"),
        (b"vp09".as_slice(), "VP9"),
        (b"mp4v".as_slice(), "MPEG-4 Video"),
    ] {
        if bytes.windows(4).any(|window| window == fourcc) {
            return Some(label);
        }
    }
    None
}

fn extract_mpeg_audio(file: &mut File, prefix: &[u8], file_size: u64) -> Ed2kMediaMetadata {
    let mut media = Ed2kMediaMetadata::default();
    let audio_start = parse_id3v2(prefix, &mut media);
    parse_id3v1(file, file_size, &mut media);
    if let Some((bitrate_kbps, frame_offset)) = find_mpeg_audio_frame(prefix, audio_start) {
        media.bitrate_kbps = bitrate_kbps;
        let trailer = u64::from(file_size >= 128 && has_id3v1(file, file_size));
        let audio_bytes = file_size
            .saturating_sub(frame_offset as u64)
            .saturating_sub(trailer * 128);
        if bitrate_kbps != 0 {
            media.length_seconds =
                u32::try_from(audio_bytes.saturating_mul(8) / (u64::from(bitrate_kbps) * 1_000))
                    .unwrap_or(u32::MAX);
        }
    }
    media
}

fn parse_id3v2(bytes: &[u8], media: &mut Ed2kMediaMetadata) -> usize {
    if bytes.len() < 10 || &bytes[..3] != b"ID3" {
        return 0;
    }
    let version = bytes[3];
    if !matches!(version, 3 | 4) || bytes[6..10].iter().any(|byte| byte & 0x80 != 0) {
        return 0;
    }
    let tag_size = syncsafe_u32(&bytes[6..10]) as usize;
    let end = 10usize.saturating_add(tag_size).min(bytes.len());
    let mut offset = 10usize;
    while offset.saturating_add(10) <= end {
        let id = &bytes[offset..offset + 4];
        if id.iter().all(|byte| *byte == 0) {
            break;
        }
        let size_bytes = &bytes[offset + 4..offset + 8];
        let frame_size = if version == 4 {
            if size_bytes.iter().any(|byte| byte & 0x80 != 0) {
                break;
            }
            syncsafe_u32(size_bytes) as usize
        } else {
            u32::from_be_bytes(size_bytes.try_into().unwrap()) as usize
        };
        let body_start = offset + 10;
        let Some(body_end) = body_start.checked_add(frame_size) else {
            break;
        };
        if body_end > end {
            break;
        }
        let target = match id {
            b"TPE1" => Some(&mut media.artist),
            b"TALB" => Some(&mut media.album),
            b"TIT2" => Some(&mut media.title),
            _ => None,
        };
        if let Some(target) = target
            && let Some(text) = decode_id3_text(&bytes[body_start..body_end])
        {
            *target = text;
        }
        offset = body_end;
    }
    10usize.saturating_add(tag_size)
}

fn syncsafe_u32(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .take(4)
        .fold(0u32, |value, byte| (value << 7) | u32::from(byte & 0x7f))
}

fn decode_id3_text(bytes: &[u8]) -> Option<String> {
    let (&encoding, body) = bytes.split_first()?;
    let text = match encoding {
        0 => body.iter().map(|byte| char::from(*byte)).collect(),
        1 => decode_utf16(body, None),
        2 => decode_utf16(body, Some(true)),
        3 => String::from_utf8_lossy(body).into_owned(),
        _ => return None,
    };
    nonempty_media_text(&text)
}

fn decode_utf16(bytes: &[u8], force_big_endian: Option<bool>) -> String {
    let (big_endian, body) = match force_big_endian {
        Some(value) => (value, bytes),
        None if bytes.starts_with(&[0xfe, 0xff]) => (true, &bytes[2..]),
        None if bytes.starts_with(&[0xff, 0xfe]) => (false, &bytes[2..]),
        None => (false, bytes),
    };
    let words = body.as_chunks::<2>().0.iter().map(|pair| {
        if big_endian {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from_le_bytes([pair[0], pair[1]])
        }
    });
    char::decode_utf16(words)
        .map(|value| value.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

fn parse_id3v1(file: &mut File, file_size: u64, media: &mut Ed2kMediaMetadata) {
    if file_size < 128 || file.seek(SeekFrom::End(-128)).is_err() {
        return;
    }
    let mut trailer = [0u8; 128];
    if file.read_exact(&mut trailer).is_err() || &trailer[..3] != b"TAG" {
        return;
    }
    if media.title.is_empty() {
        media.title = latin1_field(&trailer[3..33]);
    }
    if media.artist.is_empty() {
        media.artist = latin1_field(&trailer[33..63]);
    }
    if media.album.is_empty() {
        media.album = latin1_field(&trailer[63..93]);
    }
}

fn has_id3v1(file: &mut File, file_size: u64) -> bool {
    if file_size < 128 || file.seek(SeekFrom::End(-128)).is_err() {
        return false;
    }
    let mut signature = [0u8; 3];
    file.read_exact(&mut signature).is_ok() && signature == *b"TAG"
}

fn latin1_field(bytes: &[u8]) -> String {
    let text = bytes
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| char::from(*byte))
        .collect::<String>();
    nonempty_media_text(&text).unwrap_or_default()
}

fn nonempty_media_text(text: &str) -> Option<String> {
    let value = text
        .trim_matches(|character: char| character == '\0' || character.is_whitespace())
        .chars()
        .take(MAX_TEXT_CHARS)
        .collect::<String>();
    (!value.is_empty()).then_some(value)
}

fn find_mpeg_audio_frame(bytes: &[u8], start: usize) -> Option<(u32, usize)> {
    let search_start = start.min(bytes.len());
    for offset in search_start..bytes.len().saturating_sub(3) {
        let header = u32::from_be_bytes(bytes[offset..offset + 4].try_into().ok()?);
        if header & 0xffe0_0000 != 0xffe0_0000 {
            continue;
        }
        let version = (header >> 19) & 0x03;
        let layer = (header >> 17) & 0x03;
        let bitrate_index = ((header >> 12) & 0x0f) as usize;
        let sample_rate_index = (header >> 10) & 0x03;
        if version == 1 || layer == 0 || bitrate_index == 0 || bitrate_index == 15 {
            continue;
        }
        if sample_rate_index == 3 {
            continue;
        }
        let table: &[u16; 16] = match (version == 3, layer) {
            (true, 3) => &[
                0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0,
            ],
            (true, 2) => &[
                0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0,
            ],
            (true, 1) => &[
                0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0,
            ],
            (false, 3) => &[
                0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0,
            ],
            (false, _) => &[
                0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0,
            ],
            (true, _) => continue,
        };
        return Some((u32::from(table[bitrate_index]), offset));
    }
    None
}

fn extract_riff(bytes: &[u8], file_size: u64) -> Ed2kMediaMetadata {
    if bytes.len() < 12 || &bytes[..4] != b"RIFF" {
        return Ed2kMediaMetadata::default();
    }
    let mut media = Ed2kMediaMetadata::default();
    let form = &bytes[8..12];
    let mut wave_byte_rate = 0u32;
    parse_riff_chunks(&bytes[12..], form, &mut media, &mut wave_byte_rate);
    if form == b"AVI " && media.length_seconds != 0 && media.bitrate_kbps == 0 {
        media.bitrate_kbps = u32::try_from(
            (file_size.saturating_mul(8) / u64::from(media.length_seconds) + 500) / 1_000,
        )
        .unwrap_or(u32::MAX);
    }
    media
}

fn parse_riff_chunks(
    mut bytes: &[u8],
    form: &[u8],
    media: &mut Ed2kMediaMetadata,
    wave_byte_rate: &mut u32,
) {
    while bytes.len() >= 8 {
        let id = &bytes[..4];
        let size = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
        let Some(end) = 8usize.checked_add(size) else {
            break;
        };
        // A normal WAVE data chunk is much larger than our header window. Its
        // declared size plus the already parsed byte rate is sufficient for the
        // duration; never require the payload bytes to be resident.
        if id == b"data" && form == b"WAVE" {
            let byte_rate = u64::from(*wave_byte_rate);
            if let Some(length_seconds) = (size as u64).checked_div(byte_rate) {
                media.length_seconds = u32::try_from(length_seconds).unwrap_or(u32::MAX);
            }
            if end > bytes.len() {
                break;
            }
        }
        if end > bytes.len() {
            break;
        }
        let body = &bytes[8..end];
        match id {
            b"fmt " if form == b"WAVE" && body.len() >= 16 => {
                let format = u16::from_le_bytes(body[..2].try_into().unwrap());
                let byte_rate = u32::from_le_bytes(body[8..12].try_into().unwrap());
                *wave_byte_rate = byte_rate;
                media.bitrate_kbps = byte_rate.saturating_mul(8).saturating_add(500) / 1_000;
                media.codec = codec_from_wave_format(format).to_string();
            }
            b"data" if form == b"WAVE" => {}
            b"avih" if form == b"AVI " && body.len() >= 20 => {
                let micros = u64::from(u32::from_le_bytes(body[..4].try_into().unwrap()));
                let frames = u64::from(u32::from_le_bytes(body[16..20].try_into().unwrap()));
                media.length_seconds =
                    u32::try_from(micros.saturating_mul(frames) / 1_000_000).unwrap_or(u32::MAX);
            }
            b"strh" if form == b"AVI " && body.len() >= 8 && &body[..4] == b"vids" => {
                media.codec = fourcc(&body[4..8]);
            }
            b"LIST" if body.len() >= 4 => {
                let list_type = &body[..4];
                if list_type == b"INFO" {
                    parse_riff_info(&body[4..], media);
                } else {
                    parse_riff_chunks(&body[4..], form, media, wave_byte_rate);
                }
            }
            _ => {}
        }
        let padded_end = end.saturating_add(size & 1);
        if padded_end > bytes.len() {
            break;
        }
        bytes = &bytes[padded_end..];
    }
}

fn parse_riff_info(mut bytes: &[u8], media: &mut Ed2kMediaMetadata) {
    while bytes.len() >= 8 {
        let id = &bytes[..4];
        let size = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
        let Some(end) = 8usize.checked_add(size) else {
            break;
        };
        if end > bytes.len() {
            break;
        }
        let text = String::from_utf8_lossy(&bytes[8..end]);
        if let Some(value) = nonempty_media_text(&text) {
            match id {
                b"INAM" => media.title = value,
                b"IART" => media.artist = value,
                b"IPRD" => media.album = value,
                _ => {}
            }
        }
        let padded_end = end.saturating_add(size & 1);
        if padded_end > bytes.len() {
            break;
        }
        bytes = &bytes[padded_end..];
    }
}

fn codec_from_wave_format(format: u16) -> &'static str {
    match format {
        0x0001 => "PCM",
        0x0003 => "IEEE Float",
        0x0050 => "MPEG",
        0x0055 => "MP3",
        0x00ff => "AAC",
        0x0161 => "WMA",
        0x2000 => "AC-3",
        _ => "WAVE",
    }
}

fn fourcc(bytes: &[u8]) -> String {
    nonempty_media_text(&String::from_utf8_lossy(bytes)).unwrap_or_default()
}

fn extract_asf(bytes: &[u8], extension: &str) -> Ed2kMediaMetadata {
    const HEADER: [u8; 16] = [
        0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11, 0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce,
        0x6c,
    ];
    const FILE_PROPERTIES: [u8; 16] = [
        0xa1, 0xdc, 0xab, 0x8c, 0x47, 0xa9, 0xcf, 0x11, 0x8e, 0xe4, 0x00, 0xc0, 0x0c, 0x20, 0x53,
        0x65,
    ];
    if !bytes.starts_with(&HEADER) {
        return Ed2kMediaMetadata::default();
    }
    let mut media = Ed2kMediaMetadata {
        codec: extension.to_ascii_uppercase(),
        ..Default::default()
    };
    if let Some(offset) = bytes
        .windows(16)
        .position(|window| window == FILE_PROPERTIES)
        && offset.saturating_add(104) <= bytes.len()
    {
        let play_100ns = u64::from_le_bytes(bytes[offset + 64..offset + 72].try_into().unwrap());
        let preroll_ms = u64::from_le_bytes(bytes[offset + 80..offset + 88].try_into().unwrap());
        media.length_seconds = u32::try_from(
            play_100ns / 10_000_000 - (preroll_ms / 1_000).min(play_100ns / 10_000_000),
        )
        .unwrap_or(u32::MAX);
        media.bitrate_kbps =
            u32::from_le_bytes(bytes[offset + 100..offset + 104].try_into().unwrap()) / 1_000;
    }
    media
}

fn extract_real_media(bytes: &[u8], extension: &str) -> Ed2kMediaMetadata {
    if !bytes.starts_with(b".RMF") {
        return Ed2kMediaMetadata::default();
    }
    let mut media = Ed2kMediaMetadata {
        codec: extension.to_ascii_uppercase(),
        ..Default::default()
    };
    if let Some(offset) = bytes.windows(4).position(|window| window == b"PROP")
        && offset.saturating_add(38) <= bytes.len()
    {
        media.bitrate_kbps =
            u32::from_be_bytes(bytes[offset + 14..offset + 18].try_into().unwrap()) / 1_000;
        media.length_seconds =
            u32::from_be_bytes(bytes[offset + 34..offset + 38].try_into().unwrap()) / 1_000;
    }
    if let Some(offset) = bytes.windows(4).position(|window| window == b"CONT") {
        parse_real_content(&bytes[offset..], &mut media);
    }
    media
}

fn parse_real_content(bytes: &[u8], media: &mut Ed2kMediaMetadata) {
    if bytes.len() < 12 {
        return;
    }
    let mut offset = 10usize;
    for field in [&mut media.title, &mut media.artist] {
        if offset.saturating_add(2) > bytes.len() {
            return;
        }
        let len = u16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        let Some(end) = offset.checked_add(len) else {
            return;
        };
        if end > bytes.len() {
            return;
        }
        *field =
            nonempty_media_text(&String::from_utf8_lossy(&bytes[offset..end])).unwrap_or_default();
        offset = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn extracts_id3_text_and_mpeg_properties() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        write_synthetic_mp3(temp.path());

        let media = extract_media_metadata(temp.path(), "sample.mp3");
        assert_eq!(media.artist, "Example Artist");
        assert_eq!(media.album, "Example Album");
        assert_eq!(media.title, "Example Title");
        assert_eq!(media.bitrate_kbps, 128);
        assert_eq!(media.length_seconds, 10);
        assert!(media.codec.is_empty(), "stock does not publish MP3 codec");
    }

    #[test]
    fn extracts_aiff_metadata_and_properties_with_symphonia() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        write_synthetic_aiff(temp.path());

        let media = extract_media_metadata(temp.path(), "sample.aiff");
        assert_eq!(media.artist, "Example Artist");
        assert_eq!(media.album, "Example Album");
        assert_eq!(media.title, "Example Title");
        assert_eq!(media.length_seconds, 1);
        assert_eq!(media.bitrate_kbps, 1_412);
        assert_eq!(media.codec, "AIFF");
    }

    #[tokio::test]
    async fn shared_catalog_media_survives_runtime_restart_from_source_path() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("catalog-media.mp3");
        let runtime_root = temp.path().join("runtime");
        write_synthetic_mp3(&source);

        let file_hash = {
            let runtime = super::super::Ed2kTransferRuntime::load_or_create(&runtime_root).unwrap();
            let summary = runtime
                .ingest_local_file(&source, "catalog-media.mp3")
                .await
                .unwrap();
            let catalog = runtime.shared_catalog();
            let guard = catalog.read().await;
            let entry = guard
                .iter()
                .find(|entry| entry.file_hash == summary.file_hash)
                .unwrap();
            assert_eq!(entry.media.artist, "Example Artist");
            assert_eq!(entry.media.bitrate_kbps, 128);
            summary.file_hash
        };

        let reloaded = super::super::Ed2kTransferRuntime::load_or_create(&runtime_root).unwrap();
        let catalog = reloaded.shared_catalog();
        let guard = catalog.read().await;
        let entry = guard
            .iter()
            .find(|entry| entry.file_hash == file_hash)
            .unwrap();
        assert_eq!(entry.media.artist, "Example Artist");
        assert_eq!(entry.media.album, "Example Album");
        assert_eq!(entry.media.title, "Example Title");
        assert_eq!(entry.media.length_seconds, 10);
        assert_eq!(entry.media.bitrate_kbps, 128);
    }

    #[test]
    fn extracts_wave_properties_and_info_tags() {
        let mut body = Vec::new();
        push_riff_chunk(
            &mut body,
            b"fmt ",
            &[1, 0, 2, 0, 0x44, 0xac, 0, 0, 0x10, 0xb1, 2, 0, 4, 0, 16, 0],
        );
        let mut info = b"INFO".to_vec();
        push_riff_chunk(&mut info, b"INAM", b"Wave Title\0");
        push_riff_chunk(&mut info, b"IART", b"Wave Artist\0");
        push_riff_chunk(&mut body, b"LIST", &info);
        push_riff_chunk(&mut body, b"data", &vec![0u8; 176_400]);
        let mut wave = b"RIFF".to_vec();
        wave.extend_from_slice(&(body.len() as u32 + 4).to_le_bytes());
        wave.extend_from_slice(b"WAVE");
        wave.extend_from_slice(&body);
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), wave).unwrap();

        let media = extract_media_metadata(temp.path(), "sample.wav");
        assert_eq!(media.title, "Wave Title");
        assert_eq!(media.artist, "Wave Artist");
        assert_eq!(media.codec, "PCM");
        assert_eq!(media.bitrate_kbps, 1_411);
        assert_eq!(media.length_seconds, 1);
    }

    fn id3_text_frame(id: &[u8; 4], value: &str) -> Vec<u8> {
        let mut frame = id.to_vec();
        frame.extend_from_slice(&((value.len() + 1) as u32).to_be_bytes());
        frame.extend_from_slice(&[0, 0, 3]);
        frame.extend_from_slice(value.as_bytes());
        frame
    }

    fn write_synthetic_mp3(path: &Path) {
        let mut file = File::create(path).unwrap();
        let frames = [
            id3_text_frame(b"TPE1", "Example Artist"),
            id3_text_frame(b"TALB", "Example Album"),
            id3_text_frame(b"TIT2", "Example Title"),
        ]
        .concat();
        file.write_all(b"ID3\x03\0\0").unwrap();
        file.write_all(&syncsafe_bytes(frames.len() as u32))
            .unwrap();
        file.write_all(&frames).unwrap();
        // MPEG-1 Layer III, 128 kbps, 44.1 kHz followed by ten seconds of bytes.
        file.write_all(&[0xff, 0xfb, 0x90, 0x00]).unwrap();
        file.write_all(&vec![0u8; 160_000]).unwrap();
        file.flush().unwrap();
    }

    fn write_synthetic_aiff(path: &Path) {
        let frames = [
            id3_text_frame(b"TPE1", "Example Artist"),
            id3_text_frame(b"TALB", "Example Album"),
            id3_text_frame(b"TIT2", "Example Title"),
        ]
        .concat();
        let mut id3 = b"ID3\x03\0\0".to_vec();
        id3.extend_from_slice(&syncsafe_bytes(frames.len() as u32));
        id3.extend_from_slice(&frames);

        let mut common = Vec::new();
        common.extend_from_slice(&2u16.to_be_bytes());
        common.extend_from_slice(&44_100u32.to_be_bytes());
        common.extend_from_slice(&16u16.to_be_bytes());
        common.extend_from_slice(&[0x40, 0x0e, 0xac, 0x44, 0, 0, 0, 0, 0, 0]);

        let mut sound = vec![0; 8 + 44_100 * 2 * 2];
        sound[..4].copy_from_slice(&0u32.to_be_bytes());
        sound[4..8].copy_from_slice(&0u32.to_be_bytes());

        let mut form = b"AIFF".to_vec();
        push_aiff_chunk(&mut form, b"COMM", &common);
        push_aiff_chunk(&mut form, b"ID3 ", &id3);
        push_aiff_chunk(&mut form, b"SSND", &sound);
        let mut aiff = b"FORM".to_vec();
        aiff.extend_from_slice(&(form.len() as u32).to_be_bytes());
        aiff.extend_from_slice(&form);
        std::fs::write(path, aiff).unwrap();
    }

    fn syncsafe_bytes(value: u32) -> [u8; 4] {
        [
            ((value >> 21) & 0x7f) as u8,
            ((value >> 14) & 0x7f) as u8,
            ((value >> 7) & 0x7f) as u8,
            (value & 0x7f) as u8,
        ]
    }

    fn push_riff_chunk(target: &mut Vec<u8>, id: &[u8; 4], body: &[u8]) {
        target.extend_from_slice(id);
        target.extend_from_slice(&(body.len() as u32).to_le_bytes());
        target.extend_from_slice(body);
        if !body.len().is_multiple_of(2) {
            target.push(0);
        }
    }

    fn push_aiff_chunk(target: &mut Vec<u8>, id: &[u8; 4], body: &[u8]) {
        target.extend_from_slice(id);
        target.extend_from_slice(&(body.len() as u32).to_be_bytes());
        target.extend_from_slice(body);
        if !body.len().is_multiple_of(2) {
            target.push(0);
        }
    }
}
