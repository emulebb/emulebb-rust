use super::*;
use crate::persistence_owner::category::{CategoryCommand, CategorySharingContext};

impl EmulebbCore {
    pub async fn categories(&self) -> Result<Vec<Category>> {
        let state = self.state.lock().await;
        self.persistence_owner.check_coherent_state()?;
        Ok(state.categories.values().cloned().collect())
    }

    pub async fn category(&self, category_id: i64) -> Result<Option<Category>> {
        let state = self.state.lock().await;
        self.persistence_owner.check_coherent_state()?;
        Ok(state.categories.get(&category_id).cloned())
    }

    pub async fn category_by_name(&self, name: &str) -> Result<Option<Category>> {
        anyhow::ensure!(
            emulebb_metadata::valid_category_name(name),
            "invalid category name"
        );
        let state = self.state.lock().await;
        self.persistence_owner.check_coherent_state()?;
        Ok(state
            .categories
            .values()
            .find(|category| category.name.eq_ignore_ascii_case(name))
            .cloned())
    }

    pub async fn create_category(&self, request: CategoryCreate) -> Result<Category> {
        let draft = Category {
            id: 0,
            name: categories::normalize_category_name(request.name)?,
            temp_dir: categories::resolve_category_path(&self.profile_dir, request.temp_dir, None)?,
            destination_dir: categories::resolve_category_path(
                &self.profile_dir,
                request.destination_dir,
                None,
            )?,
            comment: request.comment.unwrap_or_default(),
        };
        let sharing = self.category_sharing_context();
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        owner
            .category(CategoryCommand::Create {
                value: draft,
                sharing,
            })
            .await??
            .context("category was not created")
    }

    pub async fn update_category(
        &self,
        id: i64,
        request: CategoryUpdate,
    ) -> Result<Option<Category>> {
        let path = |value| -> Result<Option<Option<String>>> {
            if matches!(value, NullableStringField::Missing) {
                Ok(None)
            } else {
                Ok(Some(categories::resolve_category_path(
                    &self.profile_dir,
                    value,
                    None,
                )?))
            }
        };
        let sharing = self.category_sharing_context();
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        Ok(owner
            .category(CategoryCommand::Update {
                id,
                temp: path(request.temp_dir)?,
                destination: path(request.destination_dir)?,
                comment: request.comment,
                sharing,
            })
            .await??)
    }

    pub async fn delete_category(&self, id: i64) -> Result<Option<Category>> {
        let sharing = self.category_sharing_context();
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        Ok(owner
            .category(CategoryCommand::Delete { id, sharing })
            .await??)
    }

    pub(crate) fn category_sharing_context(&self) -> CategorySharingContext {
        CategorySharingContext {
            runtime: Arc::clone(&self.ed2k_transfers),
            incoming: Arc::clone(&self.category_incoming_dir),
            root_change: Arc::clone(&self.shared_root_change),
            probe_sender: Arc::downgrade(&self.category_probe_sender),
        }
    }
}
