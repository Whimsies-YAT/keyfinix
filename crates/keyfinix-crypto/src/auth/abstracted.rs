use core::hash::Hasher;

use siphasher::sip128::Hasher128;

use super::{AssocHasher, HasAssoc};

/// An associated data for a field named by a static string
///
/// Used to add key-value pairs to the authentication chain. Common uses include:
/// - User IDs: `push_field("user", user_id)`
/// - Object IDs: `push_field("post", post_id)`
/// - Timestamps: `push_field("expires", expiry_ts)`
///
/// The key must be a static string for type safety, while the value can be any type
/// that can be converted to bytes.
pub struct FieldAssoc<T: AsRef<[u8]>, const ID1: u64, const ID2: u64> {
    key: &'static str,
    value: T,
}

impl<T: AsRef<[u8]>, const ID1: u64, const ID2: u64> FieldAssoc<T, ID1, ID2> {
    pub fn new(key: &'static str, value: T) -> Self {
        Self { key, value }
    }
}

impl<T: AsRef<[u8]>, const ID1: u64, const ID2: u64> HasAssoc for FieldAssoc<T, ID1, ID2> {
    const TYPE_ID: (u64, u64) = (ID1, ID2);

    fn push_row_level_assoc(&self, hasher: &mut AssocHasher) {
        let key = self.key.as_bytes();
        // we must bind length here, this is the internal semantics of an element and cannot possibly be protected using high level construction
        hasher.write_u64(key.len() as u64);
        hasher.write(key);
        hasher.write(self.value.as_ref());
    }
}

/// A generic byte-based associated data with compile-time type IDs
///
/// This type is intended to be type-aliased for specific use cases, providing
/// type-safe associated data with unique type IDs. The type IDs should be
/// cryptographically random to prevent collisions.
///
/// # Example
///
/// ```
/// use keyfinix_crypto::auth::{AssocEncoder, abstracted::AsBytesAssoc};
///
/// // Type alias for a key ID association
/// type KeyIdAssoc<T> = AsBytesAssoc<T, 0xda677ba4b6144780, 0x8365567554a2eee7>;
///
/// // Usage
/// let key_id = KeyIdAssoc::new("alice@example.com");
/// let encoder = AssocEncoder::new(0x6a09e667f3bcc908, 0xbb67ae8584caa73b);
/// let auth = encoder.push_assoc(&key_id);
/// let secret = auth.finish();
/// ```
///
/// The type parameters ID1 and ID2 should be unique random 64-bit integers to
/// ensure the uniqueness of the association type.
pub struct AsBytesAssoc<T: AsRef<[u8]>, const ID1: u64, const ID2: u64> {
    data: T,
}

impl<T: AsRef<[u8]>, const ID1: u64, const ID2: u64> AsBytesAssoc<T, ID1, ID2> {
    pub fn new(data: T) -> Self {
        Self { data }
    }
}

impl<T: AsRef<[u8]>, const ID1: u64, const ID2: u64> HasAssoc for AsBytesAssoc<T, ID1, ID2> {
    const TYPE_ID: (u64, u64) = (ID1, ID2);

    fn push_row_level_assoc(&self, hasher: &mut AssocHasher) {
        hasher.write(self.data.as_ref());
    }
}

/// Generate associated data from an unordered map of key-value pairs
///
/// This type is intended to be type-aliased for specific use cases, providing
/// type-safe associated data with unique type IDs. The type IDs should be
/// cryptographically random to prevent collisions.
pub struct MapAssoc<
    'a,
    K: AsRef<[u8]> + 'a,
    V: HasAssoc + 'a,
    I: IntoIterator<Item = (&'a K, &'a V)> + Clone,
    const ID1: u64,
    const ID2: u64,
> {
    items: I,
}

impl<
    'a,
    K: AsRef<[u8]> + 'a,
    V: HasAssoc + 'a,
    I: IntoIterator<Item = (&'a K, &'a V)> + Clone,
    const ID1: u64,
    const ID2: u64,
> MapAssoc<'a, K, V, I, ID1, ID2>
{
    pub fn new(items: I) -> Self {
        Self { items }
    }
}

impl<
    'a,
    K: AsRef<[u8]> + 'a,
    V: HasAssoc + 'a,
    I: IntoIterator<Item = (&'a K, &'a V)> + Clone,
    const ID1: u64,
    const ID2: u64,
> HasAssoc for MapAssoc<'a, K, V, I, { ID1 }, { ID2 }>
{
    const TYPE_ID: (u64, u64) = (ID1, ID2);

    fn push_row_level_assoc(&self, hasher: &mut AssocHasher) {
        let hasher_copy = *hasher;
        let mut fold = 0;
        let mut len = 0;
        for (key, value) in self.items.clone() {
            let mut kv_hasher = hasher_copy.clone();
            let key_ref = key.as_ref();
            kv_hasher.write_u64(key_ref.len() as u64);
            kv_hasher.hash(key.as_ref());
            value.push_row_level_assoc(&mut kv_hasher);
            fold ^= kv_hasher.finish128().as_u128();
            len += key_ref.len();
        }
        hasher.write_u128(fold);
        hasher.write_u64(len as u64);
    }
}
