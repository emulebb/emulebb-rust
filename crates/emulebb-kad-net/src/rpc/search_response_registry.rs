use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};

use emulebb_kad_proto::NodeId;
use parking_lot::Mutex;

use super::{RpcInner, RpcManager};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SearchResponseKey {
    target: NodeId,
    endpoint: SocketAddr,
}

#[derive(Default)]
pub(super) struct SearchResponseRegistry {
    registrations: Mutex<HashMap<SearchResponseKey, usize>>,
}

impl SearchResponseRegistry {
    fn register(&self, key: SearchResponseKey) {
        let mut registrations = self.registrations.lock();
        let references = registrations.entry(key).or_default();
        *references = references
            .checked_add(1)
            .expect("search response registration refcount overflow");
    }

    fn unregister(&self, key: SearchResponseKey) {
        let mut registrations = self.registrations.lock();
        let Some(references) = registrations.get_mut(&key) else {
            return;
        };
        if *references > 1 {
            *references -= 1;
        } else {
            registrations.remove(&key);
        }
    }

    pub(super) fn contains(&self, target: NodeId, endpoint: SocketAddr) -> bool {
        self.registrations
            .lock()
            .contains_key(&SearchResponseKey { target, endpoint })
    }
}

/// Keeps one phase-2 Kad search-response correlation active until dropped.
///
/// Registrations are refcounted so concurrent traversals for the same target
/// and endpoint cannot unregister each other prematurely.
#[must_use = "dropping the guard unregisters the phase-2 search response"]
pub struct SearchResponseRegistration {
    inner: Weak<RpcInner>,
    key: SearchResponseKey,
}

impl Drop for SearchResponseRegistration {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade() {
            inner.search_response_registry.unregister(self.key);
        }
    }
}

impl RpcManager {
    /// Register a phase-2 `SEARCH_RES` expected from `endpoint` for `target`.
    ///
    /// The returned guard owns the registration lifetime and must be retained
    /// while streamed responses are expected.
    pub fn register_search_response(
        &self,
        target: NodeId,
        endpoint: SocketAddr,
    ) -> SearchResponseRegistration {
        let key = SearchResponseKey { target, endpoint };
        self.inner.search_response_registry.register(key);
        SearchResponseRegistration {
            inner: Arc::downgrade(&self.inner),
            key,
        }
    }
}
