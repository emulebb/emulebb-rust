//! Runtime category operations for the REST controller surface.

use std::{
    collections::{BTreeMap, Bound},
    sync::Arc,
};

use anyhow::{Result, ensure};
use emulebb_ed2k::ed2k_transfer::Ed2kTransferRuntime;
use emulebb_metadata::MetadataStore;
use tokio::sync::Mutex;

use crate::{
    Category, CategoryCreate, CategoryUpdate, CoreState,
    categories::{PR_NORMAL, apply_category_create, apply_category_update},
    profile_state,
};

pub(crate) async fn categories(state: &Arc<Mutex<CoreState>>) -> Vec<Category> {
    state.lock().await.categories.values().cloned().collect()
}

pub(crate) async fn category(state: &Arc<Mutex<CoreState>>, category_id: u32) -> Option<Category> {
    state.lock().await.categories.get(&category_id).cloned()
}

pub(crate) async fn create_category(
    state: &Arc<Mutex<CoreState>>,
    metadata_store: &MetadataStore,
    request: CategoryCreate,
) -> Result<Category> {
    let mut category = Category {
        id: 0,
        name: String::new(),
        path: None,
        comment: String::new(),
        priority: PR_NORMAL,
        color: None,
    };
    apply_category_create(&mut category, request)?;
    let mut state = state.lock().await;
    let category_id = state.next_category_id;
    state.next_category_id = state.next_category_id.saturating_add(1).max(1);
    category.id = category_id;
    profile_state::persist_category(metadata_store, &category)?;
    state.categories.insert(category_id, category.clone());
    Ok(category)
}

pub(crate) async fn update_category(
    state: &Arc<Mutex<CoreState>>,
    metadata_store: &MetadataStore,
    category_id: u32,
    request: CategoryUpdate,
) -> Result<Option<Category>> {
    ensure!(category_id != 0, "default category cannot be updated");
    let mut state = state.lock().await;
    let Some(category) = state.categories.get_mut(&category_id) else {
        return Ok(None);
    };
    let mut updated = category.clone();
    apply_category_update(&mut updated, request)?;
    profile_state::persist_category(metadata_store, &updated)?;
    *category = updated.clone();
    Ok(Some(updated))
}

pub(crate) async fn delete_category(
    state: &Arc<Mutex<CoreState>>,
    metadata_store: &MetadataStore,
    transfer_runtime: &Ed2kTransferRuntime,
    category_id: u32,
) -> Result<Option<Category>> {
    ensure!(category_id != 0, "default category cannot be deleted");
    let (deleted, transfer_updates) = {
        let mut state = state.lock().await;
        let Some(deleted) = state.categories.get(&category_id).cloned() else {
            return Ok(None);
        };

        let shifted = shifted_categories_after_delete(&state.categories, category_id);
        metadata_store.delete_category(category_id)?;
        for (old_id, _) in &shifted {
            metadata_store.delete_category(*old_id)?;
        }
        for (_, category) in &shifted {
            profile_state::persist_category(metadata_store, category)?;
        }

        state.categories.remove(&category_id);
        for (old_id, _) in &shifted {
            state.categories.remove(old_id);
        }
        for (_, category) in shifted {
            state.categories.insert(category.id, category);
        }
        state.next_category_id = state
            .categories
            .keys()
            .copied()
            .max()
            .unwrap_or_default()
            .saturating_add(1)
            .max(1);

        let category_names = state
            .categories
            .iter()
            .map(|(id, category)| (*id, category.name.clone()))
            .collect::<BTreeMap<_, _>>();
        let default_name = category_names.get(&0).cloned().unwrap_or_default();
        let mut transfer_updates = Vec::new();
        for transfer in state.transfers.values_mut() {
            let new_category_id = if transfer.category_id == category_id {
                Some(0)
            } else if transfer.category_id > category_id {
                Some(transfer.category_id.saturating_sub(1))
            } else {
                None
            };
            let Some(new_category_id) = new_category_id else {
                continue;
            };
            transfer.category_id = new_category_id;
            transfer.category_name = category_names
                .get(&new_category_id)
                .cloned()
                .unwrap_or_else(|| default_name.clone());
            transfer_updates.push((transfer.hash.clone(), new_category_id));
        }
        (deleted, transfer_updates)
    };

    for (hash, category_id) in transfer_updates {
        transfer_runtime.set_category_id(&hash, category_id).await?;
    }
    Ok(Some(deleted))
}

fn shifted_categories_after_delete(
    categories: &BTreeMap<u32, Category>,
    category_id: u32,
) -> Vec<(u32, Category)> {
    categories
        .range((Bound::Excluded(category_id), Bound::Unbounded))
        .map(|(old_id, category)| {
            let mut shifted = category.clone();
            shifted.id = old_id.saturating_sub(1);
            (*old_id, shifted)
        })
        .collect()
}
