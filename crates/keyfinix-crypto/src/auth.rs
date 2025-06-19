//! Authentication code generation module optimized for hierarchical secret authentication
//!
//! This module provides a high-performance solution for generating and verifying authentication codes
//! in scenarios where:
//! 1. The input data is small (e.g., UUIDs, short strings, small structs)
//! 2. The attacker has limited control over the plaintext
//! 3. The server controls message generation (not which closes many oracle-like attacks)
//!
//! While SHA256 or other cryptographic hashes could be used, SipHash is specifically chosen because:
//! - It's significantly faster for small inputs (often 10-100x faster than SHA256)
//! - It provides sufficient security for this specific use case
//! - The performance advantage encourages developers to authenticate more context which is usually a much more feasible attack vector than breaking the authentication scheme
//!
//! # Key Features
//!
//! - Hierarchical authentication using `AssocEncoder` to chain multiple pieces of context
//! - Type-safe associated data through the `HasAssoc` trait
//! - Misuse resistance: a badly implemented authentication element should not negate the security of the rest of the system
//! - Built-in support for common primitive types and UUIDs
//! - Scope-based authentication with `ScopeAssoc`
//! - Field-level authentication with `FieldAssoc`
//!
//! # Performance Benefits
//!
//! The high performance of SipHash means you can freely add authentication context without
//! worrying about performance impact. For example, you might want to authenticate:
//!
//! - The API scope and/or database tables
//! - User ID
//! - Subject and object resource IDs
//! - Any other relevant context
//!
//! # Key Derivation Requirements
//!
//! When using this module with encryption, you MUST ensure the
//! AssocEncoder and the AEAD cipher are seeded with completely different keys.
//! The recommended approach is:
//!
//! 1. Use the `keyfinix_crypto::kdf` module to derive a master key
//! 2. Split the derived key into two separate parts:
//!    - One part for the AssocEncoder initialization
//!    - Another part for the AEAD cipher
//!
//! For example:
//! ```ignore
//! use keyfinix_crypto::{kdf, auth::AssocEncoder};
//!
//! // Derive a master key (64 bytes)
//! let mut key_bytes = [0u8; 64];
//! kdf::derive_persist_key(password, salt, &mut key_bytes)?;
//!
//! // Split into separate keys
//! let (assoc_key, cipher_key) = key_bytes.split_at(32);
//!
//! // Use separate keys for association and encryption
//! let encoder = AssocEncoder::new(/* use assoc_key */);
//! let cipher = /* initialize AEAD with cipher_key */;
//! ```
//!
//! The module is designed to be used with encryption primitives to provide
//! authenticated encryption with associated data (AEAD). It allows binding
//! encrypted data to specific contexts through a chain of associated data.
//!
//! See the `cubbyhole` and user signup/signin APIs in kirame-server for a complete example of how to use
//! this module in a real-world scenario.
//!
use core::hash::Hasher;

use abstracted::{FieldAssoc, MapAssoc};
use aes_gcm::{AeadInPlace, Nonce};
use siphasher::sip128::Hasher128;
use zeroize::{Zeroize, zeroize_flat_type};

use crate::wrapping::ZeroizingBuf;

/// Abstract-typed authentication chains
pub mod abstracted;

/// Hasher for chaining associated data that can be hashed to save space
///
/// It should be keyed by the global at rest key during initialization
///
/// Although this is SipHash and it might be tempting to use it for other things, do not
/// reuse this hasher for general hash tables or other things.
pub type AssocHasher = siphasher::sip128::SipHasher24;

/// Hash of associated data
pub type AssocHash = siphasher::sip128::Hash128;

/// Create associated data for an entity
///
/// This trait allows types to be used as part of an authentication chain.
/// While built-in implementations exist for primitive types and UUIDs,
/// you are strongly encouraged to implement this trait for your domain types
/// to gain both type safety and ergonomic benefits.
///
/// # Type Safety Benefits
///
/// By implementing this trait, you get:
/// 1. Compile-time guarantees that the right type of data is being authenticated
/// 2. Protection against accidentally swapping authentication fields
/// 3. Clear, self-documenting code showing what data is being authenticated
///
/// # Implementation Example
///
/// There are a couple levels you can do this depending on the complexity and need to reuse.
///
/// ```ignore
///
/// // Option 1:
///
/// auth.push_field::<0x1234_5678_90ab_cdef, 0xfedc_ba98_7654_3210, _>("user_id", user.id) // choose random u64 pairs
///
/// // Option 2:
///
/// type UserIdField = FieldAssoc<Uuid, 0x1234567890abcdef, 0xfedcba9876543210>; // choose random u64 pairs
///
/// auth.push_assoc(&UserIdField::new("user_id", user.id.as_bytes()))
///
/// // Option 3:
///
/// struct User {
///     id: Uuid,
///     name: String,
/// }
///
/// impl HasAssoc for User {
///     // Generate random u64 pairs, do not reuse!
///     const TYPE_ID: (u64, u64) = (0x1234_5678_90ab_cdef, 0xfedc_ba98_7654_3210);
///
///     fn push_row_level_assoc(&self, hasher: &mut AssocHasher) {
///         hasher.write_u128(self.id.as_u128()); // only write what you need to authenticate
///     }
/// }
///
/// auth.push_assoc(&user)
///
/// ```
///
/// # Implementation Requirements
///
/// 1. TYPE_ID must be unique and random for each type
/// 2. push_row_level_assoc should write any identifying data to the hasher
/// 3. The implementation should be constant-time if possible
///
/// See the built-in implementations for primitive types as reference.
pub trait HasAssoc {
    /// A type-level discriminator for the associated data to be added to the hasher
    ///
    /// It should be truly random and unique for each type. You can generate these
    /// using tools like `openssl rand -hex 16` or similar.
    const TYPE_ID: (u64, u64);

    /// Write the row level associated data (for example, user id in a user table)
    ///
    /// If the data does not need to be hashed, you can omit this method.
    fn push_row_level_assoc(&self, _hasher: &mut AssocHasher) {}
}

macro_rules! impl_has_assoc_for_prim_int {
    [
        $(
            $write_fn:ident ($ty:ty, $id0:literal, $id1:literal )
        ),* $(,)*
    ]
     => {
        $(
            impl HasAssoc for $ty {
                const TYPE_ID: (u64, u64) = ($id0, $id1);

                fn push_row_level_assoc(&self, hasher: &mut AssocHasher) {
                    hasher.$write_fn(*self);
                }
            }
        )*
    }
}

impl_has_assoc_for_prim_int![
    write_u8(u8, 0x1ca6079d42c39907, 0x7186036b2833360c),
    write_u16(u16, 0x987524695cd27b02, 0x3557f402d6780944),
    write_u32(u32, 0x7f6f700b4bc125f7, 0x7b843c24b5dfc9d6),
    write_u64(u64, 0x16984c62152e90ba, 0x498293a19eda17ab),
    write_i8(i8, 0x3c1a000c9fb1480c, 0xc8e886cd6de49955),
    write_i16(i16, 0xcc6b1308da825db7, 0x87ebd6f85d7016cd),
    write_i32(i32, 0x14622bb77c09b5d2, 0x1c14622bb77cb5d2),
    write_i64(i64, 0xec74ad345b0a5fc9, 0xf00647f7df4cdb34),
];

impl HasAssoc for uuid::Uuid {
    const TYPE_ID: (u64, u64) = (0xbc8115588b82a240, 0x68b0187508b163f9);

    fn push_row_level_assoc(&self, hasher: &mut AssocHasher) {
        hasher.write_u128(self.as_u128());
    }
}

/// A static string for secret scoping
///
/// Used to namespace authentication chains by their purpose or domain. For example:
/// - "api:cubbyhole" for cubbyhole secrets
/// - "api:user" for user authentication
/// - "db:table" for database table encryption
///
/// # Example
///
/// ```ignore
/// use keyfinix_crypto::auth::ScopeAssoc;
///
/// const API_SCOPE: ScopeAssoc = ScopeAssoc::new("api:example");
/// ```
pub struct ScopeAssoc(&'static str);

impl ScopeAssoc {
    pub const fn new(s: &'static str) -> Self {
        Self(s)
    }
}

impl HasAssoc for ScopeAssoc {
    const TYPE_ID: (u64, u64) = (0xda4425d1e2a5caf5, 0x08049764e7f4c316);

    fn push_row_level_assoc(&self, hasher: &mut AssocHasher) {
        hasher.write(self.0.as_bytes());
    }
}

#[derive(Debug, Clone, Copy)]
/// An encoder for associated data what you can chain to authenticate on multiple properties (hierarchical authentication)
///
/// Our goal here is not ultimate integrity (that is provided by the final usage of the authentication material, like pass it through a cryptographic MAC or AEAD),
///    but strictly ensuring effective compression of the authentication chain into a single 128-bit value, one-wayness, resisting substitution, splicing, length extension, state recovery, fixpoints, periodicity, finding inverse and other forms of weak state.
///    Few of these are "trivially solved" even if a cryptographic MAC is used, they do not have consideration in hierarchical authentication semantics, instead they can be slow and discourage pervasive use.
///
/// SipHash is an ARX family sponge function (or PRF) that provides theoretical resistance against finding these and are very fast for digesting a lot of small key materials,
/// it also doesn't have many pitfalls with semantics or buffering that plague MD-construction like SHA-2, has no (large) buffer so can produce output on demand, and is very fast for digesting a lot of small key materials.
/// however one of the key challenges is to ensure the independence of each input into the chain, and making sure no matter what the implementation of each element is.
///
/// # Security Properties
///
/// 1. Type Safety: Each association type has a unique TYPE_ID pair of random u64s
/// 2. Integrity of Hierarchy: No matter how one implements [`HasAssoc`], the integrity of the hierarchy itself is enforced.
/// 4. Collision Resistance: The chain is designed to never produce the same hash for different inputs, note this is different from differential collision resistance, which we do not require nor provide
/// 5. Constant Time: All operations are constant time
/// 6. Misuse Resistance: No matter how one implements [`HasAssoc`], the feed-forward step is designed to never compromise security for the rest of the authentication chain, the end of each element is clearly delimited by information implementors do not have access to
/// 7. Fast: The hash is optimized for small inputs and generally orders of magnitude faster than most
///    web-app operations so they can and are encouraged to be used generously when needed.
///
/// # Assumptions and Usage Recommendations
///
/// 1. Key Derivation: Although key recovery is designed to be not possible, you should
///    digest the key with a KDF first instead of using a shared key to seed the hasher.
///
/// 2. AD data are not confidential:
///
///    Associated data are by definition, not secret. SipHash is also not a cryptographic hash where it is proven to be hard to guess the input efficiently from output ("preimage resistance").
///    Thus you should not rely on anything passed into the hasher being reliably secret. In practice please always generate associate data from entity IDs, domain names, key fingerprints rather than secrets themselves, avoid piping large, attacker-controlled data into the encoder
///    without passing through a cryptographic digest first, that opens you up to many concerns this module is not designed to address like Denial of Service, etc.
pub struct AssocEncoder {
    count: u64,
    hasher: AssocHasher,
}

impl AssocEncoder {
    /// Create a new association encoder with a custom key
    #[inline(always)]
    pub fn new(key0: u64, key1: u64) -> Self {
        Self {
            count: 0,
            hasher: AssocHasher::new_with_keys(key0, key1),
        }
    }

    /// A built-in constant association encoder that is used to bootstrap
    /// trust chains, you can bootstrap with any static key.
    ///
    /// This are the first 2 constants for SHA-512 (FIPS 180-4)
    ///
    /// An example use of this is decrypting at-rest keys from master key.
    #[inline(always)]
    pub fn bootstrap() -> Self {
        Self::new(0x6a09e667f3bcc908, 0xbb67ae8584caa73b)
    }

    /// Adds associated data to the authentication chain with position-dependent mixing
    ///
    /// This is more complex than a typical update routine of a hash function, because they usually do not have domain separation and assume the input is validated and will not splice in unwanted semantics.
    ///
    /// this diffusion and double feed-forward step between enforces the property that collision resistance under misuse should be maintained by ensuring:
    ///
    /// 1. no two trait impls with different TYPE_ID or same TYPE_ID but different update logic
    /// 2. no two different length assoc chains (because
    ///      something that requires no semantic length extension to work is incredibly footgun to use
    ///      developers want to do shortcut and some people will use it in a way that one encryption has a context strictly an extension of another, or info silo caused internal sabotage), or
    /// 3. an adversarially implemented [`HasAssoc`] with cryptanalysis code and access to the current hasher state and key
    ///
    /// Can massage the internal hasher state to a different one coherent state, without predicting the whole prefix and reconstructing the hash from the beginning,
    /// the latter case we can't possibly resist, a lock can't resist a key owner with physical access to the lock.
    pub fn push_assoc<A: HasAssoc>(mut self, assoc: &A) -> Self {
        self.count += 1;
        // bind the length now, it also makes sure that [`AssocEncoder::finish`] leaks no intermediate state in a useful way against our goal of collision resistance
        self.hasher.write_u64(self.count);

        // Get current state, running 4 finalization rounds without modifying current registers (finish128 implicitly clones registers)
        let (cur_high, cur_low) = self.hasher.finish128().as_u64();
        // obtain the compile time type ID that is distinct for each type
        let (tid_high, tid_low) = A::TYPE_ID;

        // Mix type ID with current state, rotate by a co-prime to make sure the effect of the same "type" is almost never the same right off the bat
        // this also make sure cur_low is not accessible to the row level implementation without a pre-image attack.
        //
        // Since type_id has been feed forward in the first step, so even if the first associated data is malicious, they still:
        //  1. Can't recover the "fresh hasher" without the key to "repurpose" the hasher into a different hierarchy.
        //  2. Need a second pre-image to massage the state to something else.
        self.hasher
            .write_u64(tid_low ^ cur_high.rotate_left(17 * self.count as u32));

        // Add the row level associated data
        // even if this implementation is malicious and can tamper with any Sip register
        // they never have cur_low which will be fed forward after they return, preventing them from meaningfully massaging the state to something else coherent.
        // in more realistic threats, we want to make sure that no matter how bad the implementation is, they can't splice in non-existent auth elements into the chain or alter the chain for another one.
        assoc.push_row_level_assoc(&mut self.hasher);

        // re-bind the previous state that is not accessible to the row level implementation
        //
        // SipHash itself also uses a single non attacker controlled state to bind the length of the input,
        // even if the row level implementation somehow massage the hasher into a state from (A, B, BadElement) that for (A, C, BadElement) in a "replay" attack
        // the malicious state chain will have a different cur_low, and this feed forward will make that swapped hasher lead to incoherent state.
        //
        // additionally tid is also mixed in, diffuse by a depth-dependent amount
        //
        // ensuring that even if a second preimage attack is found for SipHash, the compromise is limited to a malicious chain that ends in the compromised [`HasAssoc`] implementation, at the exact same position.
        self.hasher
            .write_u64(tid_high.wrapping_add(self.count as u64) ^ cur_low);

        self
    }

    /// Adds a field to the authentication chain, it is probably more ergonomic to type alias [`abstracted::FieldAssoc`]
    /// unless you only need it for a single use case.
    pub fn push_field<const ID1: u64, const ID2: u64, T: AsRef<[u8]>>(
        self,
        key: &'static str,
        value: T,
    ) -> Self {
        self.push_assoc(&FieldAssoc::<T, ID1, ID2>::new(key, value))
    }

    /// Adds a map to the authentication chain, it is probably more ergonomic to type alias [`abstracted::MapAssoc`]
    /// unless you only need it for a single use case.
    pub fn push_map<'a, const ID1: u64, const ID2: u64, K: AsRef<[u8]> + 'a, V: HasAssoc + 'a>(
        self,
        map: impl IntoIterator<Item = (&'a K, &'a V)> + Clone,
    ) -> Self {
        self.push_assoc(&MapAssoc::<K, V, _, ID1, ID2>::new(map))
    }

    /// Use the given AEAD cipher to encrypt the data in place
    ///
    /// The data can only be decrypted with the exact same cipher and [`AssocEncoder`] sequence.
    ///
    /// You must generate a unique nonce for each encryption using the same cipher,
    /// regardless of the associated data.
    ///
    /// The buffer is guaranteed to be encrypted in place first and then extended.
    pub fn wrap<'a, 'c: 'a, A: AeadInPlace, B: AsMut<[u8]> + Extend<u8>>(
        self,
        cipher: &'c A,
        nonce: &'a Nonce<A::NonceSize>,
        plain: &'a mut B,
    ) {
        crate::wrapping::wrap(cipher, self, nonce, plain)
    }

    /// Use the given AEAD cipher to decrypt the data in place
    #[must_use]
    pub fn unwrap<'a, 'c: 'a, A: AeadInPlace>(
        self,
        cipher: &'c A,
        plain: &'a mut [u8],
    ) -> Result<ZeroizingBuf<'a>, crate::wrapping::WrappingError> {
        crate::wrapping::unwrap(cipher, self, plain)
    }

    /// Rekey a secret from one cipher to another
    ///
    /// You must generate a new nonce for the new cipher.
    ///
    /// Returns Ok(true) if the rekey was successful, Ok(false) if the input is already encrypted with the new key
    pub fn rekey<'a, 'c: 'a, A: AeadInPlace>(
        self,
        from: &'c A,
        to: &'c A,
        new_nonce: &'a Nonce<A::NonceSize>,
        ct: &'a mut [u8],
    ) -> Result<bool, crate::wrapping::WrappingError> {
        crate::wrapping::rekey(from, to, self, new_nonce, ct)
    }

    /// Get the final 128-bit hash of the authentication chain
    ///
    /// This is not a cryptographic Message Authentication Code (MAC) and should not be used as one.
    /// You must plug it into an AEAD, HMAC, or other form of cryptographic primitives to provide integrity, or authentication.
    pub fn finish(self) -> AssocHash {
        self.hasher.finish128()
    }
}

impl Into<AssocHash> for AssocEncoder {
    fn into(self) -> AssocHash {
        self.finish()
    }
}

impl Zeroize for AssocEncoder {
    fn zeroize(&mut self) {
        unsafe {
            zeroize_flat_type(&mut self.hasher);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn test_assoc_encoder() {
        let mut seen = HashSet::new();

        for encoder in [
            AssocEncoder::bootstrap(),
            AssocEncoder::new(0, 1),
            AssocEncoder::new(0, 2),
        ] {
            const SCOPE_1: ScopeAssoc = ScopeAssoc::new("scope1");
            const SCOPE_2: ScopeAssoc = ScopeAssoc::new("scope2");

            let assoc1 = encoder.push_assoc(&SCOPE_1);
            let assoc2 = encoder.push_assoc(&SCOPE_2);

            const ID1: u64 = 0x1234567890abcdef;
            const ID2: u64 = 0xfedcba9876543210;

            let assoc1_1 = assoc1
                .push_assoc(&SCOPE_1)
                .push_field::<ID1, ID2, _>("field1", "value1");

            let assoc1_1m = assoc1_1
                .push_assoc(&SCOPE_1)
                .push_field::<ID1, ID2, _>("field1", "value1\0");

            let assoc1_2 = assoc1
                .push_assoc(&SCOPE_2)
                .push_field::<ID1, ID2, _>("field1", "value2");
            let assoc1_2m = assoc1_2
                .push_assoc(&SCOPE_2)
                .push_field::<ID1, ID2, _>("field1\0", "value2");

            let assoc2_1 = assoc2
                .push_assoc(&SCOPE_1)
                .push_field::<ID1, ID2, _>("field1", "value1");
            let assoc2_1m = assoc2_1
                .push_assoc(&SCOPE_1)
                .push_field::<ID1, ID2, _>("field", "1value1");
            let assoc2_2 = assoc2
                .push_assoc(&SCOPE_2)
                .push_field::<ID1, ID2, _>("field1", "value2");
            let assoc2_2m = assoc2_2
                .push_assoc(&SCOPE_2)
                .push_field::<ID1, ID2, _>("field1v", "alue2");

            let hash1 = assoc1.finish().as_u128();
            let hash2 = assoc2.finish().as_u128();

            let hash1_1 = assoc1_1.finish().as_u128();
            let hash1_1m = assoc1_1m.finish().as_u128();
            let hash1_2 = assoc1_2.finish().as_u128();
            let hash1_2m = assoc1_2m.finish().as_u128();
            let hash2_1 = assoc2_1.finish().as_u128();
            let hash2_1m = assoc2_1m.finish().as_u128();
            let hash2_2 = assoc2_2.finish().as_u128();
            let hash2_2m = assoc2_2m.finish().as_u128();

            [
                hash1, hash2, hash1_1, hash1_1m, hash1_2, hash1_2m, hash2_1, hash2_1m, hash2_2,
                hash2_2m,
            ]
            .into_iter()
            .for_each(|h| {
                assert!(seen.insert(h), "hash collision: {:?}", h);
            });
        }
    }

    #[test]
    fn test_assoc_encoder_zeroize() {
        let mut encoder = AssocEncoder::bootstrap();
        encoder.push_assoc(&ScopeAssoc::new("test"));
        let hash1 = encoder.finish();
        let hash2 = encoder.finish();
        assert_eq!(hash1.as_u128(), hash2.as_u128());
        encoder.zeroize();
        let hash3 = encoder.finish();
        assert_ne!(hash1.as_u128(), hash3.as_u128());
    }
}
