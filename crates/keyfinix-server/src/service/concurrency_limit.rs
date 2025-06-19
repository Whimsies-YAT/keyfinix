use std::{
    future::Future,
    hash::{Hash, Hasher},
};

use hashbrown::HashMap;
use parking_lot::{RwLock, lock_api::RwLockUpgradableReadGuard};
use rand::RngCore;
use siphasher::sip::SipHasher;

use crate::{
    abstraction::backpressure::{BackPressureGuard, Backpressure},
    http::RateLimitKey,
};

type Map = HashMap<RateLimitKey, Backpressure>;

/// A map that limits the number of concurrent operations based on a key
pub struct ConcurrencyLimitMap<N: Send + Sync + 'static = (), const SH: usize = 64> {
    template: Backpressure,
    key: [u8; 16],
    map: [RwLock<Map>; SH],
    _phantom: std::marker::PhantomData<N>,
}

impl<N: Send + Sync + 'static, const SH: usize> ConcurrencyLimitMap<N, SH> {
    /// Create a new map
    #[must_use]
    pub fn new(template: Backpressure) -> Self {
        let map = std::array::from_fn(|_| RwLock::new(HashMap::new()));

        let mut key = [0; 16];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut key);

        Self {
            template,
            key,
            map,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Run garbage collection
    pub fn gc(&self) -> (usize, usize) {
        let (mut new_size, mut old_size) = (0, 0);
        self.map.iter().for_each(|v| {
            let mut v = v.write();
            old_size += v.len();
            v.retain(|_, v| v.fresh());
            new_size += v.len();
        });

        (new_size, old_size)
    }

    /// Get a backpressure guard
    pub fn get(&self, key: RateLimitKey) -> Option<impl Future<Output = BackPressureGuard> + Send> {
        let mut hash = SipHasher::new_with_key(&self.key);
        key.hash(&mut hash);
        #[allow(clippy::cast_possible_truncation)]
        let hash = (hash.finish() % SH as u64) as usize;

        let shard = self.map[hash].upgradable_read();

        if let Some(bp) = shard.get(&key) {
            Some(bp.acquire()?)
        } else {
            let mut shard = RwLockUpgradableReadGuard::upgrade(shard);

            let res = self.template.clone();
            shard.insert(key, res.clone());

            Some(res.acquire()?)
        }
    }
}
