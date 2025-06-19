//! A sandboxing environment that uses `AppArmor` sub-profiles and hats

use std::{
    ffi::{CStr, CString, c_char, c_int, c_ulong},
    hash::Hasher,
    marker::PhantomData,
    sync::atomic::AtomicU32,
};

use aes_gcm::{KeyInit, KeySizeUser};
use secrecy::zeroize::{Zeroize, Zeroizing, zeroize_flat_type};
use sha2::digest::typenum;
use siphasher::sip::SipHasher;

use super::Sandboxing;

#[link(name = "apparmor")]
unsafe extern "C" {
    fn aa_is_enabled() -> c_int;
    fn aa_change_hat(profile: *const c_char, token: c_ulong) -> c_int;
    fn aa_getcon(label: *mut *mut c_char, mode: *mut *mut c_char) -> c_int;
    fn aa_change_profile(profile: *const c_char) -> c_int;
}

/// Check if `AppArmor` is enabled
#[allow(unsafe_code)]
pub fn is_enabled() -> std::io::Result<bool> {
    let enabled = unsafe { aa_is_enabled() == 1 };
    if enabled {
        Ok(true)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Change into an arbitrary profile now
pub fn change_profile(profile: &str) -> std::io::Result<()> {
    let cstr = CString::new(profile).expect("Failed to allocate C String");

    #[allow(unsafe_code)]
    if unsafe { aa_change_profile(cstr.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

/// Check current `AppArmor` context
#[allow(unsafe_code)]
fn get_context() -> (String, String) {
    let mut label = std::ptr::null_mut();
    let mut mode = std::ptr::null_mut();
    let ret = unsafe { aa_getcon(&mut label, &mut mode) };
    assert!(
        ret >= 0,
        "AppArmor get context failed: {:?}",
        std::io::Error::last_os_error()
    );
    if label.is_null() {
        return (String::new(), String::new());
    }
    let label_str = unsafe { CStr::from_ptr(label) }
        .to_string_lossy()
        .into_owned();

    #[allow(clippy::cast_sign_loss, reason = "already checked above")]
    let mode_len = (ret as usize)
        .checked_sub(label_str.len() + 1)
        .expect("String length from libapparmor underflow");

    let mode_bytes = unsafe { std::slice::from_raw_parts(mode as *const u8, mode_len) };
    let mode_str = String::from_utf8_lossy(mode_bytes).to_string();
    unsafe { libc::free(label.cast::<libc::c_void>()) };
    (label_str, mode_str)
}

/// An `AppArmor` hat configuration
#[derive(Debug, Clone)]
pub struct AppArmorHat {
    profile: CString,
    hasher: SipHasher,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
pub struct AppArmorConfig {
    profile_name: CString,
}

impl AppArmorConfig {
    /// Create a new `AppArmor` hat configuration
    #[must_use]
    pub fn new(profile: &str) -> Self {
        Self {
            profile_name: CString::new(profile).expect("Invalid profile name"),
        }
    }

    /// Create a new `AppArmor` hat configuration (and enforcement mode) by querying for the current profile name
    ///
    /// Require AppArmor introspection to be allowed.
    #[must_use]
    pub fn current() -> Option<(Self, String)> {
        if !is_enabled().unwrap_or(false) {
            #[cfg(feature = "tracing")]
            tracing::warn!("AppArmor is not enabled");
            return None;
        }
        let (label, mode) = get_context();
        Some((
            Self {
                profile_name: CString::new(label).expect("Invalid profile name"),
            },
            mode,
        ))
    }

    /// Create a new sub-profile by deriving the name from the current profile
    #[must_use]
    pub fn subprofile(self, name: &str) -> Self {
        Self {
            profile_name: CString::new(format!(
                "{}//{}",
                self.profile_name.to_string_lossy(),
                name
            ))
            .expect("Invalid profile name"),
        }
    }

    pub fn create_hat(self, k0: u64, k1: u64) -> AppArmorHat {
        AppArmorHat::new(self.profile_name, k0, k1)
    }

    /// Change to a sub-profile
    pub fn change_profile(self) {
        let ret = unsafe { aa_change_profile(self.profile_name.as_ptr()) };
        assert!(ret == 0, "AppArmor change profile failed: {ret}");
    }
}

impl AppArmorHat {
    /// Create a new `AppArmor` hat environment
    ///
    /// # Panics
    /// Panics if the profile name is invalid C string
    #[must_use]
    pub fn new(profile: CString, k0: u64, k1: u64) -> Self {
        Self {
            profile,
            hasher: SipHasher::new_with_keys(k0, k1),
        }
    }

    /// Create a hat with a name
    pub fn hat(&self, name: &str) -> Self {
        let cstr = CString::new(format!("{}//{}", self.profile.to_string_lossy(), name))
            .expect("Invalid profile name");
        let mut hasher = self.hasher;
        hasher.write(name.as_bytes());
        Self {
            profile: cstr,
            hasher,
        }
    }

    /// Create a new `AppArmor` profile with a secret
    ///
    /// # Panics
    /// Panics if the profile name is invalid C string
    #[must_use]
    pub fn new_with_secret(profile: CString, secret: &str) -> Self {
        let mut hasher = SipHasher::new_with_keys(0x51c593c254811851, 0xcf8d94df6a0c18d7);
        hasher.write(secret.as_bytes());
        Self { profile, hasher }
    }
}

thread_local! {
    // we are not needing atomicity here, just to make compiler happy
    static SANDBOX_STACK: AtomicU32 = AtomicU32::new(0);
    static SANDBOX_COUNTER: AtomicU32 = AtomicU32::new(0);
}

/// An `AppArmor` hat-based sandboxing environment
pub struct AppArmorBox {
    profile: CString,
    hasher: SipHasher,
    _lock: PhantomData<*const ()>,
}

// A macro to insert token calculation directly into non-branching code
macro_rules! derive_token {
    ($hasher:expr, $challenge:expr, $depth:expr, $counter:expr) => {{
        $hasher.write_i32(unsafe { libc::gettid() });
        $hasher.write_u64($challenge);
        $hasher.write_u32($depth);
        $hasher.write_u32($counter);
        $hasher.finish()
    }};
}

#[derive(Clone, Copy, Debug)]
pub struct AppArmorChallenge(u64);

impl KeySizeUser for AppArmorChallenge {
    type KeySize = typenum::U8;
}

impl KeyInit for AppArmorChallenge {
    fn new(key: &aes_gcm::Key<Self>) -> Self {
        Self(u64::from_be_bytes(key.as_slice().try_into().unwrap()))
    }
}

impl Sandboxing for AppArmorBox {
    type Init = AppArmorHat;
    type Challenge = AppArmorChallenge;
    type Response = Zeroizing<(u32, u64)>;

    fn new(config: &Self::Init) -> Self {
        Self {
            profile: config.profile.clone(),
            hasher: config.hasher,
            _lock: PhantomData,
        }
    }

    fn try_new(config: &Self::Init) -> Option<Self>
    where
        Self: Sized,
    {
        if !is_enabled().unwrap_or(false) {
            return None;
        }
        Some(Self::new(config))
    }

    #[inline(always)]
    fn compute_response(&self, challenge: &Self::Challenge) -> Self::Response {
        let depth = SANDBOX_STACK.with(|stack| stack.load(std::sync::atomic::Ordering::Relaxed));
        let counter =
            SANDBOX_COUNTER.with(|counter| counter.load(std::sync::atomic::Ordering::Relaxed));

        let mut tmp: SipHasher = self.hasher;

        Zeroizing::new((counter, derive_token!(tmp, challenge.0, depth, counter)))
    }

    #[inline(always)]
    fn enter(&mut self, challenge: Self::Challenge) {
        // fetch the current stack depth and increment it by 1
        let depth =
            SANDBOX_STACK.with(|stack| stack.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        // fetch the current counter and increment it by 1
        let counter = SANDBOX_COUNTER
            .with(|counter| counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed));

        let mut expected_hasher = self.hasher;

        // compute the token and give it to the kernel
        let mut token = derive_token!(expected_hasher, challenge.0, depth, counter);

        let ret = unsafe { aa_change_hat(self.profile.as_ptr(), token as c_ulong) };
        assert!(ret == 0, "AppArmor hat change failed: {ret}");

        // forget about it
        token.zeroize();
        #[allow(unsafe_code)]
        unsafe {
            zeroize_flat_type(&mut expected_hasher)
        };

        // return control now
    }

    #[inline(always)]
    fn exit(mut self, response: impl Into<Self::Response>) {
        // decrement the stack depth by 1 and fetch the previous depth
        let depth =
            SANDBOX_STACK.with(|stack| stack.fetch_sub(1, std::sync::atomic::Ordering::Relaxed));

        let response = response.into();
        let counter = response.0;
        let response = response.1;

        // it was hashed with the previous depth so subtract 1
        #[allow(unused_mut)]
        let mut token = derive_token!(self.hasher, response, depth - 1, counter);

        #[allow(unsafe_code)]
        let ret = unsafe { aa_change_hat(std::ptr::null(), token as c_ulong) };
        if ret != 0 {
            unreachable!("AppArmor should have killed the process");
        }

        #[cfg(feature = "zeroize-paranoid")]
        token.zeroize();
    }
}

impl Drop for AppArmorBox {
    fn drop(&mut self) {
        unsafe { zeroize_flat_type(&mut self.hasher) };
    }
}
