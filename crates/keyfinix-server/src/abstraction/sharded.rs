use std::{
    hash::{BuildHasher, Hash, RandomState},
    marker::PhantomData,
};

use hashbrown::HashMap;
use parking_lot::{MappedRwLockReadGuard, RwLock, RwLockReadGuard};

/// A sharded map
pub struct ShardedMap<K: Hash, T, const N: usize, S: BuildHasher = RandomState> {
    build_hasher: S,
    locks: [RwLock<T>; N],
    _marker: PhantomData<K>,
}

impl<K: Hash, T, const N: usize, S: BuildHasher> ShardedMap<K, T, N, S> {
    /// Create a new sharded map
    pub fn new_from_fn(build_hasher: S, f: impl Fn(usize) -> T) -> Self {
        Self {
            build_hasher,
            locks: std::array::from_fn(|i| RwLock::new(f(i))),
            _marker: PhantomData,
        }
    }

    /// Read from the sharded map
    pub fn read(&self, key: &K) -> RwLockReadGuard<T> {
        let hash = self.build_hasher.hash_one(key);
        #[allow(clippy::cast_possible_truncation)]
        let index = hash as usize % N;
        self.locks[index].read()
    }

    /// Read from the sharded map and then apply a function to the result
    pub fn get_then<'a, R, F: FnOnce(u64, RwLockReadGuard<'a, T>) -> R>(
        &'a self,
        key: &'a K,
        f: F,
    ) -> R {
        let hash = self.build_hasher.hash_one(key);
        #[allow(clippy::cast_possible_truncation)]
        let index = hash as usize % N;
        f(hash, self.locks[index].read())
    }
}

impl<K: Hash + Eq, V, const N: usize, S: BuildHasher> ShardedMap<K, HashMap<K, V>, N, S> {
    /// Get a value from the sharded map
    pub fn get<'a>(&'a self, key: &'a K) -> Option<MappedRwLockReadGuard<'a, V>> {
        self.get_then(key, |_, guard| {
            RwLockReadGuard::try_map(guard, |map: &HashMap<K, V>| map.get(key)).ok()
        })
    }
}

impl<K: Hash, T: Default, const N: usize> Default for ShardedMap<K, T, N, RandomState> {
    /// Create a new sharded map with default values
    fn default() -> Self {
        Self::new_from_fn(RandomState::new(), |_| T::default())
    }
}
