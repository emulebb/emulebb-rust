/// Stable operating-system identity for one filesystem object.
///
/// The identity is meaningful only on the machine and volume where it was
/// observed. It is deliberately paired with timestamps by
/// [`NativeFileFingerprint`] because filesystems may eventually reuse IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeFileIdentity {
    Unix {
        device_id: u64,
        inode_number: u64,
    },
    WindowsLowResolution {
        volume_serial_number: u32,
        file_index: u64,
    },
    WindowsHighResolution {
        volume_serial_number: u64,
        file_id: u128,
    },
}

impl NativeFileIdentity {
    const STORAGE_VERSION: u8 = 1;

    pub(crate) fn storage_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(18);
        bytes.push(Self::STORAGE_VERSION);
        match self {
            Self::Unix {
                device_id,
                inode_number,
            } => {
                bytes.push(1);
                bytes.extend_from_slice(&device_id.to_le_bytes());
                bytes.extend_from_slice(&inode_number.to_le_bytes());
            }
            Self::WindowsLowResolution {
                volume_serial_number,
                file_index,
            } => {
                bytes.push(2);
                bytes.extend_from_slice(&volume_serial_number.to_le_bytes());
                bytes.extend_from_slice(&file_index.to_le_bytes());
            }
            Self::WindowsHighResolution {
                volume_serial_number,
                file_id,
            } => {
                bytes.push(3);
                bytes.extend_from_slice(&volume_serial_number.to_le_bytes());
                bytes.extend_from_slice(&file_id.to_le_bytes());
            }
        }
        bytes
    }

    pub(crate) fn from_storage_bytes(bytes: &[u8]) -> Option<Self> {
        let mut cursor = StorageCursor::new(bytes);
        if cursor.read_u8()? != Self::STORAGE_VERSION {
            return None;
        }
        let identity = match cursor.read_u8()? {
            1 => Self::Unix {
                device_id: cursor.read_u64()?,
                inode_number: cursor.read_u64()?,
            },
            2 => Self::WindowsLowResolution {
                volume_serial_number: cursor.read_u32()?,
                file_index: cursor.read_u64()?,
            },
            3 => Self::WindowsHighResolution {
                volume_serial_number: cursor.read_u64()?,
                file_id: cursor.read_u128()?,
            },
            _ => return None,
        };
        cursor.is_finished().then_some(identity)
    }
}

/// One filesystem timestamp with its full native subsecond value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeFileTimestamp {
    pub seconds: i64,
    pub nanoseconds: u32,
}

impl NativeFileTimestamp {
    #[must_use]
    pub const fn new(seconds: i64, nanoseconds: u32) -> Option<Self> {
        if nanoseconds < 1_000_000_000 {
            Some(Self {
                seconds,
                nanoseconds,
            })
        } else {
            None
        }
    }
}

/// Exact stat baseline used to decide whether persisted hashes remain reusable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeFileFingerprint {
    pub identity: NativeFileIdentity,
    pub size_bytes: u64,
    pub modified: NativeFileTimestamp,
    pub changed: Option<NativeFileTimestamp>,
}

impl NativeFileFingerprint {
    const STORAGE_VERSION: u8 = 1;

    /// Return whether `current` is safe to reuse without re-hashing.
    ///
    /// Exact stable identity, size, modification time, and change time must all
    /// match. A fingerprint whose available timestamps contain no subsecond
    /// signal is treated as coarse and therefore never reusable: an in-place,
    /// same-size rewrite inside one coarse timestamp tick must not silently keep
    /// an obsolete ED2K hash.
    #[must_use]
    pub fn safely_matches(&self, current: &Self) -> bool {
        self == current && self.has_subsecond_signal()
    }

    pub(crate) fn storage_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(59);
        bytes.push(Self::STORAGE_VERSION);
        match self.identity {
            NativeFileIdentity::Unix {
                device_id,
                inode_number,
            } => {
                bytes.push(1);
                bytes.extend_from_slice(&device_id.to_le_bytes());
                bytes.extend_from_slice(&inode_number.to_le_bytes());
            }
            NativeFileIdentity::WindowsLowResolution {
                volume_serial_number,
                file_index,
            } => {
                bytes.push(2);
                bytes.extend_from_slice(&volume_serial_number.to_le_bytes());
                bytes.extend_from_slice(&file_index.to_le_bytes());
            }
            NativeFileIdentity::WindowsHighResolution {
                volume_serial_number,
                file_id,
            } => {
                bytes.push(3);
                bytes.extend_from_slice(&volume_serial_number.to_le_bytes());
                bytes.extend_from_slice(&file_id.to_le_bytes());
            }
        }
        bytes.extend_from_slice(&self.size_bytes.to_le_bytes());
        append_timestamp(&mut bytes, self.modified);
        if let Some(changed) = self.changed {
            bytes.push(1);
            append_timestamp(&mut bytes, changed);
        } else {
            bytes.push(0);
        }
        bytes
    }

    pub(crate) fn from_storage_bytes(bytes: &[u8]) -> Option<Self> {
        let mut cursor = StorageCursor::new(bytes);
        if cursor.read_u8()? != Self::STORAGE_VERSION {
            return None;
        }
        let identity = match cursor.read_u8()? {
            1 => NativeFileIdentity::Unix {
                device_id: cursor.read_u64()?,
                inode_number: cursor.read_u64()?,
            },
            2 => NativeFileIdentity::WindowsLowResolution {
                volume_serial_number: cursor.read_u32()?,
                file_index: cursor.read_u64()?,
            },
            3 => NativeFileIdentity::WindowsHighResolution {
                volume_serial_number: cursor.read_u64()?,
                file_id: cursor.read_u128()?,
            },
            _ => return None,
        };
        let size_bytes = cursor.read_u64()?;
        let modified = cursor.read_timestamp()?;
        let changed = match cursor.read_u8()? {
            0 => None,
            1 => Some(cursor.read_timestamp()?),
            _ => return None,
        };
        cursor.is_finished().then_some(Self {
            identity,
            size_bytes,
            modified,
            changed,
        })
    }

    fn has_subsecond_signal(&self) -> bool {
        self.modified.nanoseconds != 0
            || self
                .changed
                .is_some_and(|timestamp| timestamp.nanoseconds != 0)
    }
}

fn append_timestamp(bytes: &mut Vec<u8>, timestamp: NativeFileTimestamp) {
    bytes.extend_from_slice(&timestamp.seconds.to_le_bytes());
    bytes.extend_from_slice(&timestamp.nanoseconds.to_le_bytes());
}

struct StorageCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> StorageCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read<const N: usize>(&mut self) -> Option<[u8; N]> {
        let end = self.offset.checked_add(N)?;
        let value = self.bytes.get(self.offset..end)?.try_into().ok()?;
        self.offset = end;
        Some(value)
    }

    fn read_u8(&mut self) -> Option<u8> {
        Some(self.read::<1>()?[0])
    }

    fn read_u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.read()?))
    }

    fn read_u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.read()?))
    }

    fn read_u128(&mut self) -> Option<u128> {
        Some(u128::from_le_bytes(self.read()?))
    }

    fn read_i64(&mut self) -> Option<i64> {
        Some(i64::from_le_bytes(self.read()?))
    }

    fn read_timestamp(&mut self) -> Option<NativeFileTimestamp> {
        NativeFileTimestamp::new(self.read_i64()?, self.read_u32()?)
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_identity_storage_roundtrips_every_variant() {
        for identity in [
            NativeFileIdentity::Unix {
                device_id: 7,
                inode_number: 11,
            },
            NativeFileIdentity::WindowsLowResolution {
                volume_serial_number: 13,
                file_index: 17,
            },
            NativeFileIdentity::WindowsHighResolution {
                volume_serial_number: 19,
                file_id: 23,
            },
        ] {
            assert_eq!(
                NativeFileIdentity::from_storage_bytes(&identity.storage_bytes()),
                Some(identity)
            );
        }
    }

    fn fingerprint(modified_ns: u32, changed_ns: Option<u32>) -> NativeFileFingerprint {
        NativeFileFingerprint {
            identity: NativeFileIdentity::Unix {
                device_id: 7,
                inode_number: 11,
            },
            size_bytes: 1024,
            modified: NativeFileTimestamp::new(1_700_000_000, modified_ns).unwrap(),
            changed: changed_ns
                .map(|nanoseconds| NativeFileTimestamp::new(1_700_000_001, nanoseconds).unwrap()),
        }
    }

    #[test]
    fn exact_precise_fingerprint_is_reusable() {
        let baseline = fingerprint(123_456_789, Some(234_567_890));

        assert!(baseline.safely_matches(&baseline));
    }

    #[test]
    fn coarse_fingerprint_is_never_reusable() {
        let baseline = fingerprint(0, Some(0));

        assert!(!baseline.safely_matches(&baseline));
    }

    #[test]
    fn changed_identity_or_timestamp_is_not_reusable() {
        let baseline = fingerprint(123_456_789, Some(234_567_890));
        let mut changed_identity = baseline.clone();
        changed_identity.identity = NativeFileIdentity::Unix {
            device_id: 7,
            inode_number: 12,
        };
        let changed_timestamp = fingerprint(123_456_788, Some(234_567_890));

        assert!(!baseline.safely_matches(&changed_identity));
        assert!(!baseline.safely_matches(&changed_timestamp));
    }

    #[test]
    fn rejects_out_of_range_nanoseconds() {
        assert!(NativeFileTimestamp::new(0, 999_999_999).is_some());
        assert!(NativeFileTimestamp::new(0, 1_000_000_000).is_none());
    }

    #[test]
    fn storage_round_trip_preserves_every_identity_kind() {
        let identities = [
            NativeFileIdentity::Unix {
                device_id: 7,
                inode_number: 11,
            },
            NativeFileIdentity::WindowsLowResolution {
                volume_serial_number: 13,
                file_index: 17,
            },
            NativeFileIdentity::WindowsHighResolution {
                volume_serial_number: 19,
                file_id: u128::MAX - 23,
            },
        ];

        for identity in identities {
            let fingerprint = NativeFileFingerprint {
                identity,
                size_bytes: u64::MAX - 29,
                modified: NativeFileTimestamp::new(-31, 123_456_789).unwrap(),
                changed: Some(NativeFileTimestamp::new(37, 987_654_321).unwrap()),
            };

            assert_eq!(
                NativeFileFingerprint::from_storage_bytes(&fingerprint.storage_bytes()),
                Some(fingerprint)
            );
        }
    }

    #[test]
    fn storage_decoder_rejects_unknown_or_trailing_data() {
        let fingerprint = fingerprint(123_456_789, None);
        let mut unknown_version = fingerprint.storage_bytes();
        unknown_version[0] = 2;
        let mut trailing = fingerprint.storage_bytes();
        trailing.push(0);

        assert!(NativeFileFingerprint::from_storage_bytes(&unknown_version).is_none());
        assert!(NativeFileFingerprint::from_storage_bytes(&trailing).is_none());
    }
}
