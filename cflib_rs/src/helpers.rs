use simple_parse::{SpRead, SpWrite};
use std::ptr::copy_nonoverlapping;
use std::sync::atomic::{AtomicU8, Ordering};

/// Crappy busy loop over a u8
pub fn acquire(lock: &u8) {
    #[allow(clippy::cast_ref_to_mut)]
    let atomic_lock: &mut AtomicU8 = unsafe{&mut *(lock as *const _ as *mut _)};
    loop {
        // If currently 0, set to 1
        match atomic_lock.compare_exchange(0, 1, Ordering::Acquire, Ordering::Acquire) {
            Ok(_) => break,
            _ => continue,
        };
    }
}
/// Sets the lock to its unlocked state
pub fn release(lock: &u8) {
    #[allow(clippy::cast_ref_to_mut)]
    let atomic_lock: &mut AtomicU8 = unsafe{&mut *(lock as *const _ as *mut _)};
    atomic_lock.store(0, Ordering::Release);
}

#[derive(SpRead, SpWrite, Debug)]
pub struct GenericBuf<'a> {
    capacity: &'a u64,
    len: &'a u64,
    start: &'a u8,
}
impl GenericBuf<'_> {
    pub fn set(&mut self, new_val: &[u8]) {
        #[allow(clippy::cast_ref_to_mut)]
        let buf_len: &mut u64 = unsafe{&mut *(self.len as *const _ as *mut _)};
        let mut write_len = new_val.len();
        if write_len > *self.capacity as usize {
            write_len = *self.capacity as usize;
        }
        *buf_len = 0;
        // copy the bytes into
        unsafe {
            copy_nonoverlapping(new_val.as_ptr(), self.start as *const _ as *mut u8, write_len);
        }
        *buf_len = write_len as u64;
    }

    pub fn get(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self.start as *const u8, *self.len as _)
        }
    }
}

pub struct LockGuard<'a, T: Sized> {
    val: T,
    lock: &'a u8,
}
impl<'a, T> LockGuard<'a, T> {
    pub fn new(val: T, lock: &'a u8) -> Self {
        Self {
            val,
            lock,
        }
    }
}
impl<'a, T> Drop for LockGuard<'a, T> {
    fn drop(&mut self) {
        release(self.lock);
    }
}

use std::ops::{Deref, DerefMut};
impl<T> Deref for LockGuard<'_, T>
where T: Sized {
    type Target = T;

    fn deref(&self) -> &T {
        &self.val
    }
}
impl<T> DerefMut for LockGuard<'_, T>
where T: Sized
{
    fn deref_mut(&mut self) -> &mut T {
        &mut self.val
    }
}