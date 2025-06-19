use core::fmt::Debug;

use aes_gcm::{KeyInit, KeySizeUser};
use secrecy::zeroize::ZeroizeOnDrop;
use sha2::digest::consts::U0;

#[cfg(all(feature = "apparmor", target_os = "linux"))]
pub mod apparmor;

/// Protected memory abstraction
#[cfg(feature = "protected-memory")]
pub mod protected_memory;

/// A trait for setting up a thread sandboxing environment
pub trait Sandboxing: 'static {
    /// Initialization parameters
    type Init: Debug + Clone + Send + Sync + 'static;

    /// The type of the challenge that is passed to the setup function
    type Challenge: KeyInit;

    /// The type of the response that need to be used to exit the sandboxing environment
    type Response: ZeroizeOnDrop;

    /// Create a new sandboxing environment assuming the environment is available
    fn new(config: &Self::Init) -> Self;

    /// Create a new sandboxing environment
    ///
    /// Return `None` if the sandboxing environment is not available
    fn try_new(config: &Self::Init) -> Option<Self>
    where
        Self: Sized;

    /// Precompute the response for a given challenge
    #[must_use]
    fn compute_response(&self, challenge: &Self::Challenge) -> Self::Response;

    /// Set up the sandboxing environment
    ///
    /// Callers should be prepared for an abrupt termination is the sandbox is initialized with [`Self::new`] with an incorrect configuration
    fn enter(&mut self, challenge: Self::Challenge);

    /// Exit the sandboxing environment
    ///
    /// Callers should be prepared for an abrupt termination of the process if the response is invalid
    ///
    /// If this value is dropped without calling `exit` the transition will become unrecoverable
    fn exit(self, response: impl Into<Self::Response>);
}

/// A sandboxing environment that does nothing
#[derive(Default, Clone, Copy)]
pub struct NoSandbox;

#[derive(Default, Clone, Copy, Debug)]
pub struct NoSandboxChallenge;

impl KeySizeUser for NoSandboxChallenge {
    type KeySize = U0;
}

impl KeyInit for NoSandboxChallenge {
    fn new(_key: &aes_gcm::Key<Self>) -> Self {
        Self
    }
}

impl Sandboxing for NoSandbox {
    type Init = ();
    type Challenge = NoSandboxChallenge;
    type Response = ();

    fn new(_config: &Self::Init) -> Self {
        Self
    }

    fn try_new(_config: &Self::Init) -> Option<Self> {
        Some(Self)
    }

    fn compute_response(&self, _challenge: &Self::Challenge) -> Self::Response {
        ()
    }

    fn enter(&mut self, _challenge: Self::Challenge) {}

    fn exit(self, _response: impl Into<Self::Response>) {}
}
