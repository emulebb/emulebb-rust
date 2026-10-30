use super::*;

impl EmulebbCore {
    pub async fn categories(&self) -> Vec<Category> {
        category_runtime::categories(&self.state).await
    }

    pub async fn category(&self, category_id: u32) -> Option<Category> {
        category_runtime::category(&self.state, category_id).await
    }

    pub async fn create_category(&self, request: CategoryCreate) -> Result<Category> {
        let _category_guard = self.category_mutation_gate.lock().await;
        category_runtime::create_category(&self.state, &self.metadata_store, request).await
    }

    pub async fn update_category(
        &self,
        category_id: u32,
        request: CategoryUpdate,
    ) -> Result<Option<Category>> {
        let _category_guard = self.category_mutation_gate.lock().await;
        category_runtime::update_category(&self.state, &self.metadata_store, category_id, request)
            .await
    }

    pub async fn delete_category(&self, category_id: u32) -> Result<Option<Category>> {
        let state = Arc::clone(&self.state);
        let transfer_runtime = Arc::clone(&self.ed2k_transfers);
        let category_gate = Arc::clone(&self.category_mutation_gate);
        tokio::spawn(async move {
            let _category_guard = category_gate.lock_owned().await;
            category_runtime::delete_category(&state, &transfer_runtime, category_id).await
        })
        .await
        .context("category deletion task panicked")?
    }
}
