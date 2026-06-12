#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataPeerCredit {
    pub user_hash: String,
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
}
