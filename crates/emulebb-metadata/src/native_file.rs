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

    fn has_subsecond_signal(&self) -> bool {
        self.modified.nanoseconds != 0
            || self
                .changed
                .is_some_and(|timestamp| timestamp.nanoseconds != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
