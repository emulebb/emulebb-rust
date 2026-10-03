use std::time::Duration;

pub(super) const OFFER_FILES_CAPABILITY_VERSION: u32 = 1;
pub(super) const OFFER_FILES_LOCAL_BATCH_MAX: u32 = 200;
pub(super) const OFFER_FILES_LOCAL_RECORDS_PER_SECOND: u32 = 400;
pub(super) const OFFER_FILES_NEGOTIATION_WAIT: Duration = Duration::from_secs(2);
pub(super) const OFFER_FILES_LEGACY_MIN_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OfferFilesPolicy {
    pub(super) batch_max: u32,
    pub(super) min_interval_ms: u32,
    pub(super) soft_files: u32,
    pub(super) hard_files: u32,
}

impl OfferFilesPolicy {
    pub(super) fn validate(
        version: u32,
        batch_max: u32,
        min_interval_ms: u32,
        soft_files: u32,
        hard_files: u32,
    ) -> Result<Self, &'static str> {
        if version != OFFER_FILES_CAPABILITY_VERSION {
            return Err("unsupported offerfiles_v");
        }
        if soft_files == 0 {
            return Err("ST_SOFTFILES must be non-zero");
        }
        if batch_max == 0 {
            return Err("offerfiles_batch_max must be non-zero");
        }
        if min_interval_ms == 0 {
            return Err("offerfiles_min_interval_ms must be non-zero");
        }
        if hard_files <= batch_max {
            return Err("ST_HARDFILES must be greater than offerfiles_batch_max");
        }
        Ok(Self {
            batch_max,
            min_interval_ms,
            soft_files,
            hard_files,
        })
    }

    pub(super) fn effective_batch_max(self, distinct_published: usize) -> usize {
        let remaining_soft = usize::try_from(self.soft_files)
            .unwrap_or(usize::MAX)
            .saturating_sub(distinct_published);
        let hard_boundary =
            usize::try_from(self.hard_files.saturating_sub(1)).unwrap_or(usize::MAX);
        remaining_soft
            .min(usize::try_from(self.batch_max).unwrap_or(usize::MAX))
            .min(hard_boundary)
            .min(OFFER_FILES_LOCAL_BATCH_MAX as usize)
    }

    pub(super) fn next_batch_delay(self, entries_sent: usize) -> Duration {
        let local_delay_ms = u64::try_from(entries_sent)
            .unwrap_or(u64::MAX)
            .saturating_mul(1_000)
            .div_ceil(u64::from(OFFER_FILES_LOCAL_RECORDS_PER_SECOND));
        Duration::from_millis(u64::from(self.min_interval_ms).max(local_delay_ms))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum OfferFilesCapabilityAdvertisement {
    Absent,
    Invalid(String),
    Supported(OfferFilesPolicy),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiated_policy_clamps_to_every_safety_boundary() {
        let policy = OfferFilesPolicy::validate(1, 500, 1, 350, 501).unwrap();
        assert_eq!(policy.effective_batch_max(0), 200);
        assert_eq!(policy.effective_batch_max(200), 150);
        assert_eq!(policy.effective_batch_max(350), 0);
        assert_eq!(policy.next_batch_delay(200), Duration::from_millis(500));
        assert_eq!(policy.next_batch_delay(100), Duration::from_millis(250));
    }

    #[test]
    fn negotiated_policy_rejects_incomplete_safety_envelope() {
        assert!(OfferFilesPolicy::validate(2, 200, 500, 1_000, 201).is_err());
        assert!(OfferFilesPolicy::validate(1, 0, 500, 1_000, 201).is_err());
        assert!(OfferFilesPolicy::validate(1, 200, 0, 1_000, 201).is_err());
        assert!(OfferFilesPolicy::validate(1, 200, 500, 0, 201).is_err());
        assert!(OfferFilesPolicy::validate(1, 200, 500, 1_000, 200).is_err());
    }

    #[test]
    fn negotiated_policy_can_publish_one_hundred_thousand_files_within_five_minutes() {
        let policy = OfferFilesPolicy::validate(1, 200, 500, 100_000, 201).unwrap();
        let batch_count = 100_000usize.div_ceil(policy.effective_batch_max(0));
        let elapsed_between_batches = policy
            .next_batch_delay(200)
            .mul_f64(u32::try_from(batch_count.saturating_sub(1)).unwrap_or(u32::MAX) as f64);

        assert_eq!(batch_count, 500);
        assert!(elapsed_between_batches <= Duration::from_secs(5 * 60));
    }
}
