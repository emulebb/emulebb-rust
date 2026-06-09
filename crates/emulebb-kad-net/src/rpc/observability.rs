use super::config::{RpcClassBudgetConfig, RpcWorkClass};
use super::packet_info::opcode_name;
use crate::tracker::{PacketTrackerAction, PacketTrackerBucket};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Aggregate tracker counters for one oracle request bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcTrackerBucketSnapshot {
    /// Stable oracle-style bucket label.
    pub bucket: &'static str,
    /// Count of tracked inbound requests accepted for this bucket.
    pub accepted_requests: u64,
    /// Count of ordinary tracker drops for this bucket.
    pub tracker_drops: u64,
    /// Count of massive-flood drops for this bucket.
    pub tracker_massive_drops: u64,
}

/// Aggregate response handling counters for one opcode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcResponseOpcodeSnapshot {
    /// Stable Kad opcode label.
    pub opcode: &'static str,
    /// Responses that resolved an explicit pending request.
    pub matched_pending: u64,
    /// Responses accepted via the oracle's IP/opcode tracker path.
    pub matched_tracked: u64,
    /// Responses dropped because the oracle had no matching outbound request.
    pub dropped_unrequested: u64,
    /// Packets accepted as unsolicited inbound traffic.
    pub accepted_unsolicited: u64,
}

/// Per-class outbound budget snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcWorkClassSnapshot {
    /// Stable outbound work class.
    pub class: RpcWorkClass,
    /// Configured packets-per-second budget for the class.
    pub max_outbound_pps: u32,
    /// Count of packets sent under this class.
    pub sent_packets: u64,
    /// Count of sends that had to wait for budget.
    pub delayed_packets: u64,
    /// Aggregate wait introduced by class/global budget acquisition.
    pub total_wait_millis: u64,
    /// Timestamp of the most recent successful send for this class.
    pub last_sent_at: Option<DateTime<Utc>>,
}

/// Machine-readable snapshot of Kad RPC tracker behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcObservabilitySnapshot {
    /// Count of inbound UDP payloads that failed Kad decode.
    pub decode_failures: u64,
    /// Global outbound safety cap.
    pub global_max_outbound_pps: u32,
    /// Per-bucket inbound request tracker counters.
    pub tracker_buckets: Vec<RpcTrackerBucketSnapshot>,
    /// Per-opcode response handling counters.
    pub response_opcodes: Vec<RpcResponseOpcodeSnapshot>,
    /// Per-class outbound budget counters.
    pub work_classes: Vec<RpcWorkClassSnapshot>,
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct RpcTrackerBucketCounters {
    accepted_requests: u64,
    tracker_drops: u64,
    tracker_massive_drops: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct RpcResponseCounters {
    matched_pending: u64,
    matched_tracked: u64,
    dropped_unrequested: u64,
    accepted_unsolicited: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct RpcWorkClassCounters {
    sent_packets: u64,
    delayed_packets: u64,
    total_wait_millis: u64,
    last_sent_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Default)]
pub(super) struct RpcObservabilityState {
    decode_failures: u64,
    tracker_buckets: HashMap<PacketTrackerBucket, RpcTrackerBucketCounters>,
    response_opcodes: HashMap<u8, RpcResponseCounters>,
    work_classes: HashMap<RpcWorkClass, RpcWorkClassCounters>,
}

impl RpcObservabilityState {
    pub(super) fn record_decode_failure(&mut self) {
        self.decode_failures += 1;
    }

    pub(super) fn record_tracker_action(
        &mut self,
        bucket: PacketTrackerBucket,
        action: PacketTrackerAction,
    ) {
        let counters = self.tracker_buckets.entry(bucket).or_default();
        match action {
            PacketTrackerAction::Allow => counters.accepted_requests += 1,
            PacketTrackerAction::Drop => counters.tracker_drops += 1,
            PacketTrackerAction::MassiveDrop => counters.tracker_massive_drops += 1,
        }
    }

    pub(super) fn record_response_matched_pending(&mut self, opcode_value: u8) {
        self.response_opcodes
            .entry(opcode_value)
            .or_default()
            .matched_pending += 1;
    }

    pub(super) fn record_response_matched_tracked(&mut self, opcode_value: u8) {
        self.response_opcodes
            .entry(opcode_value)
            .or_default()
            .matched_tracked += 1;
    }

    pub(super) fn record_response_dropped_unrequested(&mut self, opcode_value: u8) {
        self.response_opcodes
            .entry(opcode_value)
            .or_default()
            .dropped_unrequested += 1;
    }

    pub(super) fn record_response_accepted_unsolicited(&mut self, opcode_value: u8) {
        self.response_opcodes
            .entry(opcode_value)
            .or_default()
            .accepted_unsolicited += 1;
    }

    pub(super) fn record_work_class_send(&mut self, work_class: RpcWorkClass, wait_millis: u64) {
        let counters = self.work_classes.entry(work_class).or_default();
        counters.sent_packets += 1;
        counters.total_wait_millis += wait_millis;
        if wait_millis > 0 {
            counters.delayed_packets += 1;
        }
        counters.last_sent_at = Some(Utc::now());
    }

    pub(super) fn snapshot(
        &self,
        global_max_outbound_pps: u32,
        class_budgets: RpcClassBudgetConfig,
    ) -> RpcObservabilitySnapshot {
        let mut tracker_buckets: Vec<_> = self
            .tracker_buckets
            .iter()
            .map(|(bucket, counters)| RpcTrackerBucketSnapshot {
                bucket: bucket.label(),
                accepted_requests: counters.accepted_requests,
                tracker_drops: counters.tracker_drops,
                tracker_massive_drops: counters.tracker_massive_drops,
            })
            .collect();
        tracker_buckets.sort_by_key(|bucket| bucket.bucket);

        let mut response_opcodes: Vec<_> = self
            .response_opcodes
            .iter()
            .map(|(opcode_value, counters)| RpcResponseOpcodeSnapshot {
                opcode: opcode_name(*opcode_value),
                matched_pending: counters.matched_pending,
                matched_tracked: counters.matched_tracked,
                dropped_unrequested: counters.dropped_unrequested,
                accepted_unsolicited: counters.accepted_unsolicited,
            })
            .collect();
        response_opcodes.sort_by_key(|opcode| opcode.opcode);

        let mut work_classes = [
            RpcWorkClass::Interactive,
            RpcWorkClass::Harvest,
            RpcWorkClass::Maintenance,
            RpcWorkClass::Publish,
        ]
        .into_iter()
        .map(|work_class| {
            let counters = self
                .work_classes
                .get(&work_class)
                .copied()
                .unwrap_or_default();
            RpcWorkClassSnapshot {
                class: work_class,
                max_outbound_pps: class_budgets.max_outbound_pps_for(work_class),
                sent_packets: counters.sent_packets,
                delayed_packets: counters.delayed_packets,
                total_wait_millis: counters.total_wait_millis,
                last_sent_at: counters.last_sent_at,
            }
        })
        .collect::<Vec<_>>();
        work_classes.sort_by_key(|work_class| work_class.class.label());

        RpcObservabilitySnapshot {
            decode_failures: self.decode_failures,
            global_max_outbound_pps,
            tracker_buckets,
            response_opcodes,
            work_classes,
        }
    }
}
