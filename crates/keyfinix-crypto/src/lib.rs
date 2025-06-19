#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

/// AEAD hierarchical authentication
pub mod auth;

/// Secret Wrapping
pub mod wrapping;

/// Key Derivation Functions
#[cfg(feature = "kdf")]
pub mod kdf;
