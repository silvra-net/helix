//! Maps and sets that record every write, so the state commitment (#270) is brought up to date
//! from what a block changed instead of recomputed from everything the chain holds.
//!
//! Reading goes through `Deref` to the plain std collection, so every read API works unchanged.
//! There is deliberately no `DerefMut`: a write the commitment did not see would leave it
//! describing a state that no longer exists — on this node only, until it restarts and
//! recomputes, which is the shape of a fork (#229). Every write therefore goes through a method
//! here, and the method records the key's value from *before* the write, once per key between two
//! settlements. That pre-image is what the commitment subtracts; the current value is what it adds.
//!
//! A collection that did not grow out of the state's own history — deserialized, built from a
//! plain map, or handed out mutably as a whole — has no pre-images. It is marked
//! untracked, and the commitment is then recomputed in full, which is always correct and only
//! slower.

use std::borrow::Borrow;
use std::collections::{hash_map, HashMap, HashSet};
use std::hash::Hash;
use std::ops::Deref;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A `HashMap` whose writes are recorded for the state commitment. See the module docs.
#[derive(Clone, Debug)]
pub struct TrackedMap<K, V> {
    map: HashMap<K, V>,
    /// The value each written key held at the last settlement (`None`: it did not exist).
    touched: HashMap<K, Option<V>>,
    untracked: bool,
}

impl<K, V> Default for TrackedMap<K, V> {
    fn default() -> Self {
        Self { map: HashMap::new(), touched: HashMap::new(), untracked: true }
    }
}

impl<K, V> Deref for TrackedMap<K, V> {
    type Target = HashMap<K, V>;
    fn deref(&self) -> &HashMap<K, V> {
        &self.map
    }
}

impl<K: Eq + Hash, V: PartialEq> PartialEq for TrackedMap<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.map == other.map
    }
}

impl<K: Eq + Hash, V: Eq> Eq for TrackedMap<K, V> {}

impl<K, V> From<HashMap<K, V>> for TrackedMap<K, V> {
    fn from(map: HashMap<K, V>) -> Self {
        Self { map, touched: HashMap::new(), untracked: true }
    }
}

impl<K: Eq + Hash, V> FromIterator<(K, V)> for TrackedMap<K, V> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        HashMap::from_iter(iter).into()
    }
}

impl<'a, K, V> IntoIterator for &'a TrackedMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = hash_map::Iter<'a, K, V>;
    fn into_iter(self) -> Self::IntoIter {
        self.map.iter()
    }
}

impl<K: Serialize + Eq + Hash, V: Serialize> Serialize for TrackedMap<K, V> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.map.serialize(serializer)
    }
}

impl<'de, K: Deserialize<'de> + Eq + Hash, V: Deserialize<'de>> Deserialize<'de> for TrackedMap<K, V> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        HashMap::deserialize(deserializer).map(Self::from)
    }
}

impl<K: Eq + Hash + Clone, V: Clone> TrackedMap<K, V> {
    fn note(&mut self, key: &K) {
        if !self.untracked && !self.touched.contains_key(key) {
            self.touched.insert(key.clone(), self.map.get(key).cloned());
        }
    }

    /// The stored key equal to `key`, if there is one — what a write by borrowed key records.
    fn owned_key<Q>(&self, key: &Q) -> Option<K>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get_key_value(key).map(|(k, _)| k.clone())
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.note(&key);
        self.map.insert(key, value)
    }

    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let owned = self.owned_key(key)?;
        self.note(&owned);
        self.map.remove(key)
    }

    /// Mutable access to one value. Counts as a write whether or not the caller changes anything:
    /// an unchanged value is subtracted and added back, which cancels exactly.
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let owned = self.owned_key(key)?;
        self.note(&owned);
        self.map.get_mut(key)
    }

    pub fn entry(&mut self, key: K) -> hash_map::Entry<'_, K, V> {
        self.note(&key);
        self.map.entry(key)
    }

    /// Keeps the entries `keep` says yes to. Unlike `HashMap::retain` the predicate sees each value
    /// read-only: a predicate that also wrote would be a write nothing recorded.
    pub fn retain(&mut self, mut keep: impl FnMut(&K, &V) -> bool) {
        let gone: Vec<K> = self.map.iter().filter(|(k, v)| !keep(k, v)).map(|(k, _)| k.clone()).collect();
        for key in gone {
            self.note(&key);
            self.map.remove(&key);
        }
    }

    pub fn extend(&mut self, entries: impl IntoIterator<Item = (K, V)>) {
        for (key, value) in entries {
            self.insert(key, value);
        }
    }

    pub fn clear(&mut self) {
        let keys: Vec<K> = self.map.keys().cloned().collect();
        for key in &keys {
            self.note(key);
        }
        self.map.clear();
    }

    /// Make the map equal to `new`, writing only the entries that differ.
    pub fn replace_with(&mut self, new: HashMap<K, V>)
    where
        V: PartialEq,
    {
        self.retain(|key, _| new.contains_key(key));
        for (key, value) in new {
            if self.map.get(&key) != Some(&value) {
                self.insert(key, value);
            }
        }
    }

    /// Every value, mutably. Nothing records which of them change, so the collection drops out of
    /// incremental tracking until the next settlement recomputes it — a full pass, for a full pass.
    pub fn values_mut(&mut self) -> hash_map::ValuesMut<'_, K, V> {
        self.mark_untracked();
        self.map.values_mut()
    }

    pub fn iter_mut(&mut self) -> hash_map::IterMut<'_, K, V> {
        self.mark_untracked();
        self.map.iter_mut()
    }

    pub fn into_inner(self) -> HashMap<K, V> {
        self.map
    }
}

impl<K, V> TrackedMap<K, V> {
    fn mark_untracked(&mut self) {
        self.untracked = true;
        self.touched.clear();
    }

    pub(crate) fn is_tracked(&self) -> bool {
        !self.untracked
    }

    /// Keys written since the last settlement, with the value each held then.
    pub(crate) fn touched(&self) -> &HashMap<K, Option<V>> {
        &self.touched
    }

    /// The commitment now covers this collection as it stands: forget the pre-images and record
    /// writes from here on.
    pub(crate) fn settled(&mut self) {
        self.touched.clear();
        self.untracked = false;
    }
}

/// A `HashSet` whose writes are recorded for the state commitment. See the module docs.
#[derive(Clone, Debug)]
pub struct TrackedSet<K> {
    set: HashSet<K>,
    /// Whether each written key was present at the last settlement.
    touched: HashMap<K, bool>,
    untracked: bool,
}

impl<K> Default for TrackedSet<K> {
    fn default() -> Self {
        Self { set: HashSet::new(), touched: HashMap::new(), untracked: true }
    }
}

impl<K> Deref for TrackedSet<K> {
    type Target = HashSet<K>;
    fn deref(&self) -> &HashSet<K> {
        &self.set
    }
}

impl<K: Eq + Hash> PartialEq for TrackedSet<K> {
    fn eq(&self, other: &Self) -> bool {
        self.set == other.set
    }
}

impl<K: Eq + Hash> Eq for TrackedSet<K> {}

impl<K> From<HashSet<K>> for TrackedSet<K> {
    fn from(set: HashSet<K>) -> Self {
        Self { set, touched: HashMap::new(), untracked: true }
    }
}

impl<K: Eq + Hash> FromIterator<K> for TrackedSet<K> {
    fn from_iter<I: IntoIterator<Item = K>>(iter: I) -> Self {
        HashSet::from_iter(iter).into()
    }
}

impl<'a, K> IntoIterator for &'a TrackedSet<K> {
    type Item = &'a K;
    type IntoIter = std::collections::hash_set::Iter<'a, K>;
    fn into_iter(self) -> Self::IntoIter {
        self.set.iter()
    }
}

impl<K: Serialize + Eq + Hash> Serialize for TrackedSet<K> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.set.serialize(serializer)
    }
}

impl<'de, K: Deserialize<'de> + Eq + Hash> Deserialize<'de> for TrackedSet<K> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        HashSet::deserialize(deserializer).map(Self::from)
    }
}

impl<K: Eq + Hash + Clone> TrackedSet<K> {
    fn note(&mut self, key: &K) {
        if !self.untracked && !self.touched.contains_key(key) {
            self.touched.insert(key.clone(), self.set.contains(key));
        }
    }

    pub fn insert(&mut self, key: K) -> bool {
        self.note(&key);
        self.set.insert(key)
    }

    pub fn remove<Q>(&mut self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let Some(owned) = self.set.get(key).cloned() else {
            return false;
        };
        self.note(&owned);
        self.set.remove(key)
    }

    pub fn retain(&mut self, mut keep: impl FnMut(&K) -> bool) {
        let gone: Vec<K> = self.set.iter().filter(|k| !keep(k)).cloned().collect();
        for key in gone {
            self.note(&key);
            self.set.remove(&key);
        }
    }

    pub fn extend(&mut self, keys: impl IntoIterator<Item = K>) {
        for key in keys {
            self.insert(key);
        }
    }

    pub fn clear(&mut self) {
        let keys: Vec<K> = self.set.iter().cloned().collect();
        for key in &keys {
            self.note(key);
        }
        self.set.clear();
    }

    /// Make the set equal to `new`, writing only the keys that differ.
    pub fn replace_with(&mut self, new: HashSet<K>) {
        self.retain(|key| new.contains(key));
        for key in new {
            if !self.set.contains(&key) {
                self.insert(key);
            }
        }
    }

    pub fn into_inner(self) -> HashSet<K> {
        self.set
    }
}

impl<K> TrackedSet<K> {
    pub(crate) fn is_tracked(&self) -> bool {
        !self.untracked
    }

    pub(crate) fn touched(&self) -> &HashMap<K, bool> {
        &self.touched
    }

    pub(crate) fn settled(&mut self) {
        self.touched.clear();
        self.untracked = false;
    }
}
