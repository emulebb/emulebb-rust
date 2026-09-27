//! LowID callback intent bookkeeping.

use super::{Ed2kCallbackIntent, Ed2kTransferRuntime};

impl Ed2kTransferRuntime {
    /// Register one pending LowID callback download intent.
    pub async fn register_callback_intent(&self, intent: Ed2kCallbackIntent) {
        let mut intents = self.callback_intents.write().await;
        if !intents.iter().any(|existing| existing == &intent) {
            intents.push(intent);
        }
    }

    /// Claim the oldest pending LowID callback intent for the specified peer client-id.
    pub async fn claim_callback_intent(&self, client_id: u32) -> Option<Ed2kCallbackIntent> {
        let mut intents = self.callback_intents.write().await;
        let index = intents
            .iter()
            .position(|intent| intent.client_id == client_id)?;
        Some(intents.remove(index))
    }

    /// Claim the complete peer-centric callback source set in registration
    /// order. One LowID connect-back can then negotiate every wanted file over
    /// that already-established socket instead of consuming one intent and
    /// requiring another server/Kad callback for each A4AF relation.
    pub async fn claim_callback_intents(&self, client_id: u32) -> Vec<Ed2kCallbackIntent> {
        let mut intents = self.callback_intents.write().await;
        let mut claimed = Vec::new();
        let mut retained = Vec::with_capacity(intents.len());
        for intent in intents.drain(..) {
            if intent.client_id == client_id {
                claimed.push(intent);
            } else {
                retained.push(intent);
            }
        }
        *intents = retained;
        claimed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ed2k_transfer::Ed2kSourceHint, paths::unique_test_dir};

    fn intent(client_id: u32, hash_byte: u8) -> Ed2kCallbackIntent {
        Ed2kCallbackIntent {
            client_id,
            file_hash: hex::encode([hash_byte; 16]),
            display_name: format!("{hash_byte}.bin"),
            file_size: u64::from(hash_byte),
            source: Ed2kSourceHint {
                ip: "192.0.2.1".to_string(),
                tcp_port: 4662,
                user_hash: None,
                connect_options: None,
                file_comment: String::new(),
                file_rating: 0,
            },
        }
    }

    #[tokio::test]
    async fn callback_claim_collects_one_peers_full_a4af_set_in_order() {
        let runtime = Ed2kTransferRuntime::load_or_create(&unique_test_dir(
            "ed2k-callback-a4af-intent-claim",
        ))
        .unwrap();
        runtime.register_callback_intent(intent(17, 1)).await;
        runtime.register_callback_intent(intent(23, 2)).await;
        runtime.register_callback_intent(intent(17, 3)).await;

        let claimed = runtime.claim_callback_intents(17).await;
        assert_eq!(
            claimed
                .iter()
                .map(|intent| intent.file_hash.as_str())
                .collect::<Vec<_>>(),
            vec![hex::encode([1; 16]), hex::encode([3; 16])]
        );
        assert_eq!(runtime.claim_callback_intent(23).await, Some(intent(23, 2)));
        assert!(runtime.claim_callback_intents(17).await.is_empty());
    }
}
