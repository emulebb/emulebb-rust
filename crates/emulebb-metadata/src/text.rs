use unicode_normalization::UnicodeNormalization;

pub fn normalize_search_text(value: &str) -> String {
    value
        .nfkc()
        .flat_map(char::to_lowercase)
        .map(|ch| if ch.is_alphanumeric() { ch } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn normalize_path_key(value: &str) -> String {
    let normalized = value.nfkc().collect::<String>();
    if cfg!(windows) {
        normalized
            .chars()
            .flat_map(char::to_lowercase)
            .collect::<String>()
    } else {
        normalized
    }
}
