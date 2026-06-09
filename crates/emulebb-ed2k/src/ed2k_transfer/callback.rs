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
}
