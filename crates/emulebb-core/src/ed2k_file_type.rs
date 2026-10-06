use std::path::Path;

/// eMule's internal file families. Archive and CD-image are intentionally
/// distinct here even though both are published and searched as `Pro` on the
/// wire; stock eMule refines that broad wire family from the filename before
/// presenting or filtering results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ed2kFileType {
    Audio,
    Video,
    Image,
    Archive,
    Program,
    CdImage,
    Document,
    EmuleCollection,
}

impl Ed2kFileType {
    pub(crate) fn from_public_token(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "audio" => Some(Self::Audio),
            "video" => Some(Self::Video),
            "image" => Some(Self::Image),
            "arc" | "archive" => Some(Self::Archive),
            "pro" | "program" => Some(Self::Program),
            "iso" => Some(Self::CdImage),
            "doc" | "document" => Some(Self::Document),
            "emulecollection" => Some(Self::EmuleCollection),
            _ => None,
        }
    }

    fn from_tag(tag: &str) -> Option<Self> {
        Self::from_public_token(tag)
    }

    pub(crate) const fn internal_name(self) -> &'static str {
        match self {
            Self::Audio => "Audio",
            Self::Video => "Video",
            Self::Image => "Image",
            Self::Archive => "Arc",
            Self::Program => "Pro",
            Self::CdImage => "Iso",
            Self::Document => "Doc",
            Self::EmuleCollection => "EmuleCollection",
        }
    }

    pub(crate) const fn search_term(self) -> &'static str {
        match self {
            Self::Archive | Self::Program | Self::CdImage => "Pro",
            other => other.internal_name(),
        }
    }
}

/// Resolve a received result to the internal family used by eMule's result
/// list. A broad `Pro` tag is refined from the filename; a specific tag remains
/// authoritative. If no recognized tag exists, the filename is the fallback.
pub(crate) fn ed2k_result_file_type(claimed: &str, name: &str) -> Option<Ed2kFileType> {
    match Ed2kFileType::from_tag(claimed) {
        Some(Ed2kFileType::Program) => ed2k_file_type_by_name(name).or(Some(Ed2kFileType::Program)),
        Some(file_type) => Some(file_type),
        None => ed2k_file_type_by_name(name),
    }
}

/// Return the broad ED2K/Kad file-type tag used for publishing and search
/// constraints. This deliberately maps Archive/CD-image/Program to `Pro`.
pub(crate) fn ed2k_file_type_search_term(name: &str) -> Option<&'static str> {
    ed2k_file_type_by_name(name).map(Ed2kFileType::search_term)
}

/// Classify a filename with the stock eMule extension table plus a small set of
/// unambiguous modern formats already supported by emulebb-rust.
pub(crate) fn ed2k_file_type_by_name(name: &str) -> Option<Ed2kFileType> {
    let extension = Path::new(name)
        .extension()
        .and_then(|extension| extension.to_str())?
        .to_ascii_lowercase();
    match extension.as_str() {
        "aac" | "ac3" | "aif" | "aifc" | "aiff" | "amr" | "ape" | "au" | "aud" | "audio"
        | "cda" | "dmf" | "dsm" | "dts" | "far" | "flac" | "it" | "m1a" | "m2a" | "m4a" | "mdl"
        | "med" | "mid" | "midi" | "mka" | "mod" | "mp1" | "mp2" | "mp3" | "mpa" | "mpc"
        | "mtm" | "oga" | "ogg" | "opus" | "psm" | "ptm" | "ra" | "rmi" | "s3m" | "snd" | "stm"
        | "umx" | "wav" | "weba" | "wma" | "xm" => Some(Ed2kFileType::Audio),
        "3g2" | "3gp" | "3gp2" | "3gpp" | "amv" | "asf" | "avi" | "bik" | "divx" | "dvr-ms"
        | "flc" | "fli" | "flic" | "flv" | "hdmov" | "ifo" | "m1v" | "m2t" | "m2ts" | "m2v"
        | "m4b" | "m4v" | "mkv" | "mov" | "movie" | "mp1v" | "mp2v" | "mp4" | "mpe" | "mpeg"
        | "mpg" | "mpv" | "mpv1" | "mpv2" | "ogm" | "ogv" | "pva" | "qt" | "ram" | "ratdvd"
        | "rm" | "rmm" | "rmvb" | "rv" | "smil" | "smk" | "swf" | "tp" | "ts" | "vid" | "video"
        | "vob" | "vp6" | "webm" | "wm" | "wmv" | "xvid" => Some(Ed2kFileType::Video),
        "bmp" | "emf" | "gif" | "ico" | "jfif" | "jpe" | "jpeg" | "jpg" | "pct" | "pcx" | "pic"
        | "pict" | "png" | "psd" | "psp" | "svg" | "tga" | "tif" | "tiff" | "webp" | "wmf"
        | "wmp" | "xif" => Some(Ed2kFileType::Image),
        "7z" | "ace" | "alz" | "arc" | "arj" | "bz2" | "cab" | "cbr" | "cbz" | "gz" | "hqx"
        | "lha" | "lzh" | "msi" | "pak" | "par" | "par2" | "rar" | "sit" | "sitx" | "tar"
        | "tbz2" | "tgz" | "xpi" | "z" | "zip" => Some(Ed2kFileType::Archive),
        "apk" | "appx" | "bat" | "cmd" | "com" | "deb" | "exe" | "hta" | "js" | "jse" | "msc"
        | "rpm" | "vbe" | "vbs" | "wsf" | "wsh" => Some(Ed2kFileType::Program),
        "bin" | "bwa" | "bwi" | "bws" | "bwt" | "ccd" | "cue" | "dmg" | "img" | "iso" | "mdf"
        | "mds" | "nrg" | "sub" | "toast" => Some(Ed2kFileType::CdImage),
        "chm" | "css" | "diz" | "doc" | "docx" | "dot" | "epub" | "hlp" | "htm" | "html"
        | "mobi" | "nfo" | "pdf" | "pps" | "ppt" | "ps" | "rtf" | "text" | "txt" | "wri"
        | "xls" | "xml" => Some(Ed2kFileType::Document),
        "emulecollection" => Some(Ed2kFileType::EmuleCollection),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stock_broad_program_tag_is_refined_from_the_filename() {
        assert_eq!(
            ed2k_result_file_type("Pro", "release.7z"),
            Some(Ed2kFileType::Archive)
        );
        assert_eq!(
            ed2k_result_file_type("Pro", "release.iso"),
            Some(Ed2kFileType::CdImage)
        );
        assert_eq!(
            ed2k_result_file_type("Pro", "setup.exe"),
            Some(Ed2kFileType::Program)
        );
        assert_eq!(
            ed2k_result_file_type("Pro", "unclassified.payload"),
            Some(Ed2kFileType::Program)
        );
    }

    #[test]
    fn representative_stock_extensions_keep_their_exact_families() {
        for (name, expected) in [
            ("track.ac3", Ed2kFileType::Audio),
            ("movie.rmvb", Ed2kFileType::Video),
            ("scan.psd", Ed2kFileType::Image),
            ("bundle.cbz", Ed2kFileType::Archive),
            ("script.vbs", Ed2kFileType::Program),
            ("disc.nrg", Ed2kFileType::CdImage),
            ("manual.html", Ed2kFileType::Document),
            ("set.emulecollection", Ed2kFileType::EmuleCollection),
        ] {
            assert_eq!(ed2k_file_type_by_name(name), Some(expected), "{name}");
        }
    }

    #[test]
    fn broad_wire_terms_do_not_erase_internal_families() {
        assert_eq!(Ed2kFileType::Archive.search_term(), "Pro");
        assert_eq!(Ed2kFileType::Archive.internal_name(), "Arc");
        assert_eq!(Ed2kFileType::CdImage.search_term(), "Pro");
        assert_eq!(Ed2kFileType::CdImage.internal_name(), "Iso");
    }
}
