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
        let category =
            category_runtime::create_category(&self.state, &self.metadata_store, request).await?;
        drop(_category_guard);
        if category
            .path
            .as_ref()
            .is_some_and(|path| !path.trim().is_empty())
        {
            self.refresh_category_share_roots().await?;
        }
        Ok(category)
    }

    pub async fn update_category(
        &self,
        category_id: u32,
        request: CategoryUpdate,
    ) -> Result<Option<Category>> {
        let _category_guard = self.category_mutation_gate.lock().await;
        let previous_path = self
            .category(category_id)
            .await
            .and_then(|category| category.path);
        let category = category_runtime::update_category(
            &self.state,
            &self.metadata_store,
            category_id,
            request,
        )
        .await?;
        drop(_category_guard);
        if category
            .as_ref()
            .is_some_and(|category| category.path != previous_path)
        {
            self.refresh_category_share_roots().await?;
        }
        Ok(category)
    }

    pub async fn delete_category(&self, category_id: u32) -> Result<Option<Category>> {
        let state = Arc::clone(&self.state);
        let transfer_runtime = Arc::clone(&self.ed2k_transfers);
        let category_gate = Arc::clone(&self.category_mutation_gate);
        let category = tokio::spawn(async move {
            let _category_guard = category_gate.lock_owned().await;
            category_runtime::delete_category(&state, &transfer_runtime, category_id).await
        })
        .await
        .context("category deletion task panicked")??;
        if category
            .as_ref()
            .and_then(|category| category.path.as_ref())
            .is_some_and(|path| !path.trim().is_empty())
        {
            self.refresh_category_share_roots().await?;
        }
        Ok(category)
    }

    async fn refresh_category_share_roots(&self) -> Result<()> {
        shared_directories::sync_implicit_shared_directory_roots(self).await?;
        self.ed2k_transfers
            .refresh_complete_shared_catalog()
            .await?;
        self.start_shared_directory_monitor().await;
        self.reload_shared_directories_detached().await?;
        Ok(())
    }
}
