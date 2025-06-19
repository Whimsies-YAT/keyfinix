use core::ops::{Deref, DerefMut};

use aes_gcm::{AeadInPlace, Aes256Gcm, Nonce, Tag, aes::cipher::Unsigned};
use zeroize::Zeroize;

use crate::auth::AssocHash;

#[derive(Debug)]
pub enum WrappingError {
    InvalidDecrypt,
}

impl core::fmt::Display for WrappingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "authenticated decryption failed, either the data, key or the auth tag is invalid"
        )
    }
}

impl core::error::Error for WrappingError {}

pub type DefaultAeadEngine = Aes256Gcm;

#[derive(Debug)]
#[repr(transparent)]
/// A mutable buffer that zeroizes itself when dropped, it is used to hold sensitive data after decryption, etc.
pub struct ZeroizingBuf<'a>(pub &'a mut [u8]);

impl<'a> ZeroizingBuf<'a> {
    /// Extract the buffer without zeroizing it
    #[cfg(any(test, feature = "hazmat"))]
    pub fn disarm(self) -> &'a mut [u8] {
        let ret = unsafe { core::slice::from_raw_parts_mut(self.0.as_mut_ptr(), self.0.len()) };
        core::mem::forget(self);
        ret
    }
}

impl<'a> Deref for ZeroizingBuf<'a> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> DerefMut for ZeroizingBuf<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> Drop for ZeroizingBuf<'a> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(any(test, feature = "testing"))]
/// A nonce prefix that is ignored by the nonce reuse detection in testing
pub const TESTING_REUSABLE_NONCE_PREFIX: &[u8] = b"reused";

/// Unwrap the associated data with the cipher
#[must_use]
pub fn unwrap<'a, 'c: 'a, A: AeadInPlace>(
    cipher: &'c A,
    assoc: impl Into<AssocHash>,
    encrypted: &'a mut [u8],
) -> Result<ZeroizingBuf<'a>, WrappingError> {
    if encrypted.len() < A::TagSize::USIZE + A::NonceSize::USIZE {
        return Err(WrappingError::InvalidDecrypt);
    }

    let (rest, tag) = encrypted.split_at_mut(encrypted.len() - A::TagSize::USIZE);
    let (rest, nonce) = rest.split_at_mut(rest.len() - A::NonceSize::USIZE);

    let tag = Tag::from_slice(tag);
    let nonce = Nonce::from_slice(nonce);

    let hash: AssocHash = assoc.into();
    cipher
        .decrypt_in_place_detached(&nonce, &hash.as_bytes(), rest.as_mut(), &tag)
        .map_err(|_| {
            rest.zeroize();
            WrappingError::InvalidDecrypt
        })?;

    Ok(ZeroizingBuf(rest))
}

/// Wrap the associated data with the cipher
///
/// You must generate a unique nonce for each encryption using the same cipher,
/// regardless of the associated data.
///
/// It is guaranteed the buffer will be encrypted first and then extended.
pub fn wrap<A: AeadInPlace, B: AsMut<[u8]> + Extend<u8>>(
    cipher: &A,
    assoc: impl Into<AssocHash>,
    nonce: &Nonce<A::NonceSize>,
    plain: &mut B,
) {
    #[cfg(all(debug_assertions, any(test, feature = "testing")))]
    reuse_detection::push_used_nonce::<A>(nonce);

    let tag = cipher
        .encrypt_in_place_detached(&nonce, &assoc.into().as_bytes(), plain.as_mut())
        .unwrap();

    plain.extend(nonce.as_slice().into_iter().copied());
    plain.extend(tag.as_slice().into_iter().copied());
}

/// Rekey a secret from one cipher to another
///
/// You must pass a newly generated nonce for the new cipher.
///
/// Returns Ok(true) if the secret was rekeyed, Ok(false) if the secret is already using the new key
pub fn rekey<A: AeadInPlace>(
    from: &A,
    to: &A,
    assoc: impl Into<AssocHash>,
    new_nonce: &Nonce<A::NonceSize>,
    ct: &mut [u8],
) -> Result<bool, WrappingError> {
    #[cfg(all(debug_assertions, any(test, feature = "testing")))]
    reuse_detection::push_used_nonce::<A>(new_nonce);

    let (rest, tag_portion) = ct.split_at_mut(ct.len() - A::TagSize::USIZE);
    let (rest, nonce_portion) = rest.split_at_mut(rest.len() - A::NonceSize::USIZE);

    let old_tag = Tag::from_slice(tag_portion);
    let old_nonce = Nonce::from_slice(nonce_portion);

    let hash: AssocHash = assoc.into();
    if from
        .decrypt_in_place_detached(&old_nonce, &hash.as_bytes(), rest, &old_tag)
        .is_err()
    {
        if to
            .decrypt_in_place_detached(&old_nonce, &hash.as_bytes(), rest, &old_tag)
            .is_err()
        {
            return Err(WrappingError::InvalidDecrypt);
        }

        to.encrypt_in_place_detached(&old_nonce, &hash.as_bytes(), rest)
            .unwrap();

        return Ok(false);
    }

    let new_tag = to
        .encrypt_in_place_detached(&new_nonce, &hash.as_bytes(), rest)
        .unwrap();

    nonce_portion.copy_from_slice(new_nonce.as_slice());
    tag_portion.copy_from_slice(new_tag.as_slice());

    Ok(true)
}

#[cfg(any(test, feature = "testing"))]
mod reuse_detection {
    use super::*;

    static TESTING_USED_NONCES: std::sync::LazyLock<
        std::sync::Mutex<std::collections::HashSet<u128>>,
    > = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

    /// Push a nonce into the set of used nonces
    ///
    /// This panics if the nonce is uninitialized (equal to the default value) or has been used before
    pub fn push_used_nonce<A: AeadInPlace>(nonce: &Nonce<A::NonceSize>) {
        if nonce.as_slice().starts_with(TESTING_REUSABLE_NONCE_PREFIX) {
            return;
        }

        if nonce == &Nonce::default() {
            panic!("nonce is uninitialized");
        }

        let sip = siphasher::sip128::SipHasher13::new_with_keys(0, 0);
        let hash = sip.hash(nonce.as_slice());
        if !TESTING_USED_NONCES.lock().unwrap().insert(hash.as_u128()) {
            panic!("nonce reuse detected");
        }
    }
}

#[cfg(test)]
mod tests {
    use aes_gcm::KeyInit;
    use sha2::digest::generic_array::GenericArray;

    use crate::auth::{AssocEncoder, ScopeAssoc};

    use super::*;

    fn rng() -> [u8; 16] {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sip = siphasher::sip128::SipHasher13::new_with_keys(0, 0);

        sip.hash(
            COUNTER
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                .to_le_bytes()
                .as_ref(),
        )
        .as_bytes()
    }

    fn rng_fill(mut buf: impl AsMut<[u8]>) {
        buf.as_mut().chunks_mut(16).for_each(|chunk| {
            chunk.copy_from_slice(&rng()[..chunk.len()]);
        });
    }

    fn rng_keyinit<C: KeyInit>() -> C {
        let mut key_bytes = GenericArray::default();
        rng_fill(&mut key_bytes);
        C::new(&key_bytes)
    }

    #[test]
    fn test_wrap_unwrap() {
        let cipher = rng_keyinit::<Aes256Gcm>();
        const SCOPE_1: ScopeAssoc = ScopeAssoc::new("scope1");
        const SCOPE_2: ScopeAssoc = ScopeAssoc::new("scope2");

        const ID1: u64 = 0x1234567890abcdef;
        const ID2: u64 = 0xfedcba9876543210;

        let assoc1 = AssocEncoder::bootstrap()
            .push_assoc(&SCOPE_1)
            .push_field::<ID1, ID2, _>("field1", "value1");

        let assoc2 = AssocEncoder::bootstrap()
            .push_assoc(&SCOPE_2)
            .push_field::<ID1, ID2, _>("field1", "value2");

        assert_ne!(
            assoc1.finish().as_u128(),
            assoc2.finish().as_u128(),
            "root assoc hash collision"
        );

        let mut nonce1 = GenericArray::default();
        rng_fill(&mut nonce1);

        let mut nonce2 = GenericArray::default();
        rng_fill(&mut nonce2);

        let plain1 = b"abc_test";
        let mut plain2 = [0u8; 1543];
        rng_fill(&mut plain2);

        let mut wrapped1 = plain1.to_vec();
        let mut wrapped2 = plain2.to_vec();

        wrap(&cipher, assoc1, &nonce1, &mut wrapped1);
        wrap(&cipher, assoc2, &nonce2, &mut wrapped2);

        assert_ne!(wrapped1, wrapped2);
        assert_ne!(plain1, &*wrapped1);
        assert_ne!(plain2, *wrapped2);

        let decrypt1 = unwrap(&cipher, assoc1, &mut wrapped1).unwrap();
        let decrypt2 = unwrap(&cipher, assoc2, &mut wrapped2).unwrap();

        assert_eq!(decrypt1.as_ref(), plain1);
        assert_eq!(decrypt2.as_ref(), plain2);
    }

    #[test]
    fn test_rekey() {
        let old_cipher = rng_keyinit::<Aes256Gcm>();

        const SCOPE_1: ScopeAssoc = ScopeAssoc::new("scope1");
        const SCOPE_2: ScopeAssoc = ScopeAssoc::new("scope2");

        let assoc = AssocEncoder::bootstrap().push_assoc(&SCOPE_1);
        let wrong_assoc = AssocEncoder::bootstrap().push_assoc(&SCOPE_2);

        let mut nonce = GenericArray::default();
        rng_fill(&mut nonce);
        nonce[..TESTING_REUSABLE_NONCE_PREFIX.len()].copy_from_slice(TESTING_REUSABLE_NONCE_PREFIX);

        let pt = b"abc_test";
        let mut ct = pt.to_vec();

        wrap(&old_cipher, assoc, &nonce, &mut ct);

        let new_cipher = rng_keyinit::<Aes256Gcm>();

        let ct_clone = ct.clone();

        rekey(&old_cipher, &new_cipher, wrong_assoc, &nonce, &mut ct)
            .expect_err("rekey should fail with wrong assoc");

        let rekeyed = rekey(&old_cipher, &new_cipher, assoc, &nonce, &mut ct).unwrap();
        assert!(rekeyed);

        assert_ne!(ct, ct_clone, "Rekey should change the buffer");

        let decrypted = unwrap(&new_cipher, assoc, &mut ct).unwrap().disarm();
        assert_eq!(
            decrypted, pt,
            "Decrypted buffer should match the original plaintext"
        );

        wrap(&new_cipher, assoc, &nonce, &mut ct);

        let ct_clone = ct.clone();

        let rekeyed_noop = rekey(&old_cipher, &new_cipher, assoc, &nonce, &mut ct).unwrap();
        assert!(!rekeyed_noop, "No-op rekey should return false");

        assert_eq!(ct, ct_clone, "No-op rekey should not change the buffer");
    }
}
