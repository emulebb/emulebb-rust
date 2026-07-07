//! In-memory per-transfer corruption attribution (`CCorruptionBlackBox`).
//!
//! Mirrors the oracle `CorruptionBlackBox.cpp`: every downloaded byte range is
//! recorded against the sender IP (`ReceivedData`, fed from
//! `CPartFile::WriteToBuffer`, PartFile.cpp:4951). When AICH recovery delivers
//! a per-180 KB-block verdict for a corrupt part
//! (`CPartFile::AICHRecoveryDataAvailable`, PartFile.cpp:6555-6566), the good
//! blocks credit their recorded senders (`VerifiedData`) and the bad blocks
//! debit them (`CorruptedData`); a whole part that MD4-verifies credits all its
//! recorded senders (PartFile.cpp:5205/5225). `EvaluateData` then bans a sender
//! only when its corrupt share exceeds `CBB_BANTHRESHOLD` (32%) of its
//! corrupt+verified contribution (CorruptionBlackBox.cpp:233-309). An MD4 part
//! failure alone NEVER bans -- it only gaps the part and solicits AICH recovery
//! (PartFile.cpp:5184-5199).
//!
//! Like the oracle, the blackbox is live in-memory state per part file: it is
//! never persisted and is freed when the transfer completes
//! (PartFile.cpp:3800 `m_CorruptionBlackBox.Free()`).

use std::collections::HashMap;
use std::net::Ipv4Addr;

use super::{ED2K_EMBLOCK_SIZE, ED2K_PART_SIZE, Ed2kTransferRuntime, diag_bad_peer};

/// Max corrupted-data share (percent) before a sender is banned
/// (`CBB_BANTHRESHOLD`, CorruptionBlackBox.cpp:33). The comparison is strict
/// (`> CBB_BANTHRESHOLD`), so exactly 32% does not ban.
const CBB_BAN_THRESHOLD: u64 = 32;

/// The oracle ban reason string (`CorruptionBlackBox.cpp:290`), reused verbatim
/// for the `client_ban` diag event so soak diffing lines up with MFC.
const CORRUPT_SENDER_BAN_REASON: &str = "Identified as a sender of corrupt data";

/// Attribution state of one recorded byte range (`EBBRStatus`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BbrStatus {
    /// Received, no verdict yet (`BBR_NONE`).
    None,
    /// Covered by a passing AICH block / MD4 part verdict (`BBR_VERIFIED`).
    Verified,
    /// Covered by a failing AICH block verdict (`BBR_CORRUPTED`).
    Corrupted,
}

/// One recorded byte range of one part (`CCBBRecord`). Positions are
/// part-relative and INCLUSIVE on both ends, exactly like the oracle's
/// `m_nStartPos`/`m_nEndPos`, so the arithmetic ports 1:1.
#[derive(Debug, Clone, Copy)]
struct CbbRecord {
    start: u64,
    end: u64,
    ip: Ipv4Addr,
    status: BbrStatus,
}

impl CbbRecord {
    /// `CCBBRecord::CanMerge`: same sender + status and exactly adjacent.
    fn can_merge(&self, start: u64, end: u64, ip: Ipv4Addr, status: BbrStatus) -> bool {
        self.ip == ip && self.status == status && (start == self.end + 1 || end + 1 == self.start)
    }

    /// `CCBBRecord::Merge`: extend this record by the adjacent range.
    fn merge(&mut self, start: u64, end: u64, ip: Ipv4Addr, status: BbrStatus) -> bool {
        if self.ip != ip || self.status != status {
            return false;
        }
        if start == self.end + 1 {
            self.end = end;
        } else if end + 1 == self.start {
            self.start = start;
        } else {
            return false;
        }
        true
    }
}

/// `CorruptionBlackBoxSeams::MarkRecordOverlapAndAppendRemainders`: clamp the
/// indexed record to its overlap with `[rel_start, rel_end]`, restamp it with
/// `marked_status`, and append the untouched head/tail remainders (which keep
/// the old sender + status). Returns the number of marked bytes (0 = no
/// overlap).
fn mark_record_overlap_and_append_remainders(
    records: &mut Vec<CbbRecord>,
    index: usize,
    rel_start: u64,
    rel_end: u64,
    marked_status: BbrStatus,
) -> u64 {
    let old = records[index];
    if old.start > rel_end || old.end < rel_start {
        return 0;
    }
    let marked_start = old.start.max(rel_start);
    let marked_end = old.end.min(rel_end);
    records[index].start = marked_start;
    records[index].end = marked_end;
    records[index].status = marked_status;
    if marked_end < old.end {
        records.push(CbbRecord {
            start: marked_end + 1,
            end: old.end,
            ip: old.ip,
            status: old.status,
        });
    }
    if old.start < marked_start {
        records.push(CbbRecord {
            start: old.start,
            end: marked_start - 1,
            ip: old.ip,
            status: old.status,
        });
    }
    marked_end - marked_start + 1
}

/// Outcome of `EvaluateData` for one guilty sender IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CbbEvaluation {
    ip: Ipv4Addr,
    /// Corrupt bytes attributed to this sender, each corrupted record counted
    /// as at least one 180 KB block (CorruptionBlackBox.cpp:271).
    data_corrupt: u64,
    /// Verified bytes credited to this sender.
    data_verified: u64,
    /// Whether the corrupt share crossed `CBB_BANTHRESHOLD`.
    ban: bool,
}

/// Per-file corruption blackbox (`CCorruptionBlackBox`): records grouped per
/// part (`m_aaRecords`), plus the last hello-claimed user hash seen per sender
/// IP so a ban can cover both keys like the oracle's `FindClientByIP` ->
/// `Ban(..)` (both scopes).
#[derive(Debug, Default)]
pub(super) struct CorruptionBlackBox {
    records: Vec<Vec<CbbRecord>>,
    sender_hashes: HashMap<Ipv4Addr, [u8; 16]>,
}

impl CorruptionBlackBox {
    fn part_records(&mut self, part: usize) -> &mut Vec<CbbRecord> {
        if self.records.len() <= part {
            self.records.resize_with(part + 1, Vec::new);
        }
        &mut self.records[part]
    }

    /// `CCorruptionBlackBox::ReceivedData`: record `[abs_start, abs_end]`
    /// (absolute file offsets, inclusive) as sent by `ip`, rewriting any
    /// overlapping pending (`BBR_NONE`) records so each byte is attributed to
    /// its LAST writer -- this is what keeps mixed-writer parts (a part resumed
    /// across peers) correctly attributed per range.
    fn received_data(&mut self, abs_start: u64, abs_end: u64, ip: Ipv4Addr) {
        if abs_end - abs_start >= ED2K_PART_SIZE || abs_start > abs_end {
            debug_assert!(false, "invalid blackbox range {abs_start}..={abs_end}");
            return;
        }
        let part = usize::try_from(abs_start / ED2K_PART_SIZE).unwrap_or(usize::MAX);
        let part_start = abs_start / ED2K_PART_SIZE * ED2K_PART_SIZE;
        let mut rel_start = abs_start - part_start;
        let mut rel_end = abs_end - part_start;
        if rel_end >= ED2K_PART_SIZE {
            // Data crosses the part boundary, split it.
            rel_end = ED2K_PART_SIZE - 1;
            self.received_data(part_start + ED2K_PART_SIZE, abs_end, ip);
        }
        let mut sender_ip = ip;

        let records = self.part_records(part);
        let mut i = 0;
        while i < records.len() {
            // Check if there is already a pending entry and overwrite it.
            if records[i].status == BbrStatus::None {
                if records[i].start >= rel_start && records[i].end <= rel_end {
                    // Old one is included into the new one -> delete.
                    records.remove(i);
                    continue;
                } else if records[i].start < rel_start && records[i].end > rel_end {
                    // Old one includes the new one.
                    if sender_ip != records[i].ip {
                        // Different IP: split into 3 blocks (oracle keeps the
                        // middle for the new sender and re-adds head + tail for
                        // the old one, the tail via the post-loop add below).
                        let old_start = records[i].start;
                        let old_end = records[i].end;
                        let old_ip = records[i].ip;
                        records[i].start = rel_start;
                        records[i].end = rel_end;
                        records[i].ip = sender_ip;
                        records.push(CbbRecord {
                            start: old_start,
                            end: rel_start - 1,
                            ip: old_ip,
                            status: BbrStatus::None,
                        });
                        rel_start = rel_end + 1;
                        rel_end = old_end;
                        sender_ip = old_ip;
                        break; // done here
                    }
                } else if records[i].start >= rel_start && records[i].start <= rel_end {
                    // Old one overlaps the new one on the right side.
                    records[i].start = rel_end + 1;
                } else if records[i].end >= rel_start && records[i].end <= rel_end {
                    // Old one overlaps the new one on the left side.
                    records[i].end = rel_start - 1;
                }
            }
            i += 1;
        }

        // Locate the final adjacent record only after normalization is complete
        // (the loop above deletes/trims/splits older records).
        let merge_index = records
            .iter()
            .position(|record| record.can_merge(rel_start, rel_end, sender_ip, BbrStatus::None));
        let merged = merge_index.is_some_and(|index| {
            records[index].merge(rel_start, rel_end, sender_ip, BbrStatus::None)
        });
        if !merged {
            records.push(CbbRecord {
                start: rel_start,
                end: rel_end,
                ip: sender_ip,
                status: BbrStatus::None,
            });
        }
    }

    /// `CCorruptionBlackBox::VerifiedData`: mark `[abs_start, abs_end]`
    /// (inclusive) as verified, crediting whichever senders are recorded for
    /// those bytes.
    fn verified_data(&mut self, abs_start: u64, abs_end: u64) {
        if abs_end >= abs_start + ED2K_PART_SIZE {
            debug_assert!(false, "oversized verified range {abs_start}..={abs_end}");
            return;
        }
        let part = usize::try_from(abs_start / ED2K_PART_SIZE).unwrap_or(usize::MAX);
        let part_start = abs_start / ED2K_PART_SIZE * ED2K_PART_SIZE;
        let rel_start = abs_start - part_start;
        let rel_end = abs_end - part_start;
        if rel_end >= ED2K_PART_SIZE {
            debug_assert!(false, "verified range crosses part boundary");
            return;
        }
        let records = self.part_records(part);
        let mut i = 0;
        while i < records.len() {
            if records[i].status == BbrStatus::None || records[i].status == BbrStatus::Verified {
                mark_record_overlap_and_append_remainders(
                    records,
                    i,
                    rel_start,
                    rel_end,
                    BbrStatus::Verified,
                );
            }
            i += 1;
        }
    }

    /// `CCorruptionBlackBox::CorruptedData`: mark `[abs_start, abs_end]`
    /// (inclusive, at most one 180 KB block) as corrupted, debiting whichever
    /// senders are recorded (pending) for those bytes.
    fn corrupted_data(&mut self, abs_start: u64, abs_end: u64) {
        if abs_end - abs_start >= ED2K_EMBLOCK_SIZE {
            debug_assert!(false, "oversized corrupted range {abs_start}..={abs_end}");
            return;
        }
        let part = usize::try_from(abs_start / ED2K_PART_SIZE).unwrap_or(usize::MAX);
        let part_start = abs_start / ED2K_PART_SIZE * ED2K_PART_SIZE;
        let rel_start = abs_start - part_start;
        let rel_end = abs_end - part_start;
        if rel_end >= ED2K_PART_SIZE {
            debug_assert!(false, "corrupted range crosses part boundary");
            return;
        }
        let records = self.part_records(part);
        let mut i = 0;
        while i < records.len() {
            if records[i].status == BbrStatus::None {
                mark_record_overlap_and_append_remainders(
                    records,
                    i,
                    rel_start,
                    rel_end,
                    BbrStatus::Corrupted,
                );
            }
            i += 1;
        }
    }

    /// `CCorruptionBlackBox::EvaluateData`: collect the senders with corrupted
    /// records in `part` (skipping already-banned IPs), aggregate their
    /// corrupt/verified byte totals over ALL parts of the file, and flag for
    /// banning every sender whose corrupt share exceeds `CBB_BANTHRESHOLD`.
    /// Corrupted records count as at least one 180 KB block each; verified
    /// records count their exact size in the sender's favor
    /// (CorruptionBlackBox.cpp:264-287).
    fn evaluate_data(
        &self,
        part: usize,
        is_already_banned: impl Fn(Ipv4Addr) -> bool,
    ) -> Vec<CbbEvaluation> {
        let Some(part_records) = self.records.get(part) else {
            return Vec::new();
        };
        let mut guilty: Vec<Ipv4Addr> = Vec::new();
        for record in part_records {
            if record.status == BbrStatus::Corrupted && !guilty.contains(&record.ip) {
                guilty.push(record.ip);
            }
        }
        guilty.retain(|&ip| !is_already_banned(ip));

        let mut evaluations = Vec::with_capacity(guilty.len());
        for ip in guilty {
            let mut data_corrupt = 0u64;
            let mut data_verified = 0u64;
            for records in &self.records {
                for record in records {
                    if record.ip != ip {
                        continue;
                    }
                    match record.status {
                        // Corrupted data records are always counted as at
                        // least block size (180 KB) or more.
                        BbrStatus::Corrupted => {
                            data_corrupt += (record.end - record.start + 1).max(ED2K_EMBLOCK_SIZE);
                        }
                        BbrStatus::Verified => data_verified += record.end - record.start + 1,
                        BbrStatus::None => {}
                    }
                }
            }
            let corrupt_percentage = (data_corrupt * 100)
                .checked_div(data_verified + data_corrupt)
                .unwrap_or(0);
            evaluations.push(CbbEvaluation {
                ip,
                data_corrupt,
                data_verified,
                ban: corrupt_percentage > CBB_BAN_THRESHOLD,
            });
        }
        evaluations
    }
}

impl Ed2kTransferRuntime {
    /// Record `[start, end)` (absolute file offsets, exclusive end) of
    /// `file_hash` as sent by `ip` in the transfer's corruption blackbox
    /// (oracle `CPartFile::WriteToBuffer` -> `ReceivedData`,
    /// PartFile.cpp:4951). The hello-claimed `user_hash`, when known, is
    /// remembered per sender IP so an eventual ban covers both keys.
    pub(crate) fn cbb_record_received_data(
        &self,
        file_hash: &str,
        start: u64,
        end: u64,
        ip: Ipv4Addr,
        user_hash: Option<[u8; 16]>,
    ) {
        if end <= start {
            return;
        }
        let mut map = self.lock_corruption_blackbox();
        let blackbox = map.entry(file_hash.to_string()).or_default();
        if let Some(user_hash) = user_hash {
            blackbox.sender_hashes.insert(ip, user_hash);
        }
        blackbox.received_data(start, end - 1, ip);
    }

    /// Credit the recorded senders of `[start, end)` (exclusive end) as
    /// verified (oracle `VerifiedData` on an MD4 part success,
    /// PartFile.cpp:5205/5225, and on each good AICH block,
    /// PartFile.cpp:6560).
    pub(super) fn cbb_record_verified_data(&self, file_hash: &str, start: u64, end: u64) {
        if end <= start {
            return;
        }
        let mut map = self.lock_corruption_blackbox();
        let Some(blackbox) = map.get_mut(file_hash) else {
            return;
        };
        blackbox.verified_data(start, end - 1);
    }

    /// Debit the recorded senders of `[start, end)` (exclusive end) as corrupt
    /// (oracle `CorruptedData` on each bad AICH block, PartFile.cpp:6563).
    pub(super) fn cbb_record_corrupted_data(&self, file_hash: &str, start: u64, end: u64) {
        if end <= start {
            return;
        }
        let mut map = self.lock_corruption_blackbox();
        let Some(blackbox) = map.get_mut(file_hash) else {
            return;
        };
        blackbox.corrupted_data(start, end - 1);
    }

    /// Evaluate the blackbox after AICH verdicts landed for `part` (oracle
    /// `EvaluateData`, PartFile.cpp:6566): ban (IP + last-known user hash, 4 h
    /// `CLIENTBANTIME`) every sender whose corrupt share exceeds 32% of its
    /// corrupt+verified contribution, emitting the `client_ban` bad-peer diag
    /// event with the oracle's ban reason (UploadClient.cpp:1050).
    pub(super) fn cbb_evaluate_part(&self, file_hash: &str, part: u16) {
        let verdicts: Vec<(CbbEvaluation, Option<[u8; 16]>)> = {
            let map = self.lock_corruption_blackbox();
            let Some(blackbox) = map.get(file_hash) else {
                return;
            };
            blackbox
                .evaluate_data(usize::from(part), |ip| {
                    self.ban_store.is_banned(Some(ip), None)
                })
                .into_iter()
                .map(|evaluation| {
                    (
                        evaluation,
                        blackbox.sender_hashes.get(&evaluation.ip).copied(),
                    )
                })
                .collect()
        };
        for (evaluation, user_hash) in verdicts {
            if evaluation.ban {
                self.ban_client(Some(evaluation.ip), user_hash);
                diag_bad_peer::client_ban(
                    &evaluation.ip.to_string(),
                    user_hash,
                    CORRUPT_SENDER_BAN_REASON,
                );
                tracing::warn!(
                    file_hash,
                    ip = %evaluation.ip,
                    corrupt_bytes = evaluation.data_corrupt,
                    total_bytes = evaluation.data_corrupt + evaluation.data_verified,
                    "CorruptionBlackBox: banning sender of corrupt data"
                );
            } else {
                tracing::debug!(
                    file_hash,
                    ip = %evaluation.ip,
                    corrupt_bytes = evaluation.data_corrupt,
                    total_bytes = evaluation.data_corrupt + evaluation.data_verified,
                    "CorruptionBlackBox: corrupt sender within acceptable limit"
                );
            }
        }
    }

    /// Drop the transfer's blackbox once the file completes (oracle
    /// `m_CorruptionBlackBox.Free()` on `PerformFileComplete`,
    /// PartFile.cpp:3800).
    pub(crate) fn cbb_free(&self, file_hash: &str) {
        self.lock_corruption_blackbox().remove(file_hash);
    }

    fn lock_corruption_blackbox(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<String, CorruptionBlackBox>> {
        match self.corruption_blackbox.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}
