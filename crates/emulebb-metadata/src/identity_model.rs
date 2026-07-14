#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataLocalIdentity {
    pub identity_kind: String,
    pub public_identity: Option<Vec<u8>>,
    pub private_secret: Option<Vec<u8>>,
}
