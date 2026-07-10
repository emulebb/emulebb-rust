use super::*;

impl EmulebbCore {
    pub async fn categories(&self) -> Vec<Category> {
        category_runtime::categories(&self.state).await
    }

    pub async fn category(&self, category_id: u32) -> Option<Category> {
        category_runtime::category(&self.state, category_id).await
    }

    pub async fn create_category(&self, request: CategoryCreate) -> Result<Category> {
        category_runtime::create_category(&self.state, &self.metadata_store, request).await
    }

    pub async fn update_category(
        &self,
        category_id: u32,
        request: CategoryUpdate,
    ) -> Result<Option<Category>> {
        category_runtime::update_category(&self.state, &self.metadata_store, category_id, request)
            .await
    }

    pub async fn delete_category(&self, category_id: u32) -> Result<Option<Category>> {
        category_runtime::delete_category(
            &self.state,
            &self.metadata_store,
            &self.ed2k_transfers,
            category_id,
        )
        .await
    }
}
