use std::{
    fs::File,
    ops::{Deref, DerefMut},
    ptr::NonNull,
};

use libc::{FD_CLOEXEC, MFD_CLOEXEC, O_CLOEXEC};
use secrecy::zeroize::{Zeroize, ZeroizeOnDrop};

/// A memory region that is protected from being swapped to disk.
pub struct MemFdSecret<T: Zeroize> {
    _file: File,
    ptr: NonNull<T>,
    len: usize,
}

impl<T: Zeroize> Deref for MemFdSecret<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { self.ptr.as_ref() }
    }
}

impl<T: Zeroize> DerefMut for MemFdSecret<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.ptr.as_mut() }
    }
}

impl<T: Zeroize> MemFdSecret<T> {
    /// Create a new protected memory region.
    ///
    /// The page will be cleared on exec if `cloexec` is true.
    ///
    /// Drop will not be called on the item, zeroize will be called on close.
    ///
    /// Returns a mapping to contain `T` in zeroized form.
    pub fn new(cloexec: bool) -> Result<Self, std::io::Error> {
        use std::os::fd::FromRawFd;

        let mut fd =
            unsafe { libc::syscall(libc::SYS_memfd_secret, if cloexec { O_CLOEXEC } else { 0 }) };

        // try to use MFD_CLOEXEC if O_CLOEXEC is not supported
        // the old version of man pages used MFD_CLOEXEC instead of O_CLOEXEC
        if cloexec && fd == -1 && unsafe { *libc::__errno_location() } == libc::EINVAL {
            fd = unsafe { libc::syscall(libc::SYS_memfd_secret, MFD_CLOEXEC) };
        }

        // if still failed, try FD_CLOEXEC
        if cloexec && fd == -1 && unsafe { *libc::__errno_location() } == libc::EINVAL {
            fd = unsafe { libc::syscall(libc::SYS_memfd_secret, FD_CLOEXEC) };
        }

        if fd == -1 {
            return Err(std::io::Error::last_os_error());
        }
        // panics: never, no OS I know of returns fd numbers greater than what Rust can take (i32).
        // but just in case we can bail out here.
        let fd = fd.try_into().map_err(|_| {
            unsafe {
                libc::syscall(libc::SYS_close, fd);
            }
            std::io::Error::new(std::io::ErrorKind::Other, "failed to convert fd to i32")
        })?;

        // Immediately transfer the file descriptor to an RAII file.
        let file = unsafe { File::from_raw_fd(fd) };

        file.set_len(core::mem::size_of::<T>().try_into().unwrap())?;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                core::mem::size_of::<T>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        let mut ret = Self {
            ptr: NonNull::new(ptr.cast()).unwrap(),
            len: core::mem::size_of::<T>(),
            _file: file,
        };

        ret.zeroize();

        Ok(ret)
    }
}

/// SAFETY: This behaves like a Box<T> in a special allocation.
unsafe impl<T: Zeroize + Send> Send for MemFdSecret<T> {}

/// SAFETY: This behaves like a Box<T> in a special allocation.
unsafe impl<T: Zeroize + Sync> Sync for MemFdSecret<T> {}

impl<T: Zeroize> Zeroize for MemFdSecret<T> {
    fn zeroize(&mut self) {
        self.deref_mut().zeroize();
    }
}

impl<T: Zeroize> ZeroizeOnDrop for MemFdSecret<T> {}

impl<T: Zeroize> Drop for MemFdSecret<T> {
    fn drop(&mut self) {
        unsafe {
            self.zeroize();
            libc::munmap(self.ptr.as_ptr().cast(), self.len);
        }
    }
}

#[cfg(test)]
mod tests {

    use secrecy::zeroize::{Zeroize, zeroize_flat_type};

    use crate::protected_memory::MemFdSecret;

    #[test]
    fn test_protected_memory() {
        #[derive(Copy, Clone)]
        struct MySecret {
            username_len: u8,
            username: [u8; 16],
            password_len: u8,
            password: [u8; 16],
        }
        impl Zeroize for MySecret {
            fn zeroize(&mut self) {
                unsafe {
                    zeroize_flat_type(self);
                }
            }
        }

        for cloexec in [true, false] {
            let mut mem = MemFdSecret::<MySecret>::new(cloexec).unwrap();
            mem.username_len = 5;
            mem.password_len = 8;
            mem.username[..5].copy_from_slice(b"hello");
            mem.password[..8].copy_from_slice(b"password");
            assert_eq!(
                std::str::from_utf8(&mem.username[..mem.username_len as usize]).unwrap(),
                "hello"
            );
            assert_eq!(
                std::str::from_utf8(&mem.password[..mem.password_len as usize]).unwrap(),
                "password"
            );

            let ls_output = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg("ls -l /proc/self/fd")
                .output()
                .unwrap();
            let stdout = String::from_utf8(ls_output.stdout).unwrap();
            assert_eq!(
                !stdout.contains("memfd:") && !stdout.contains("secretmem"),
                cloexec,
                "expected children to {} possess memfd or secretmem",
                if cloexec { "not" } else { "" }
            );
        }
    }
}
