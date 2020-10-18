use simple_parse::*;
use std::ptr::copy_nonoverlapping;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::stats::*;

/// Crappy busy loop over a u8
pub fn acquire(lock: &mut AtomicU8) {
    loop {
        // If currently 0, set to 1
        match lock.compare_exchange(0, 1, Ordering::Acquire, Ordering::Acquire) {
            Ok(_) => break,
            _ => continue,
        };
    }
}
/// Sets the lock to its unlocked state
pub fn release(lock: &mut AtomicU8) {
    lock.store(0, Ordering::Release);
}

#[derive(Debug)]
pub(crate) struct GenericBuf {
    capacity: &'static mut u64,
    len: &'static mut u64,
    /// Slice of 'capacity' bytes
    buf: &'static mut [u8],
}

impl GenericBuf {
    pub fn capacity(&self) -> u64 {
        *self.capacity
    }

    /// Updates the contents of the buf
    /// If new_val is too big, it gets truncated to self.capacity()
    pub fn set(&mut self, new_val: &[u8]) {
        let mut new_len = self.capacity();
        if (new_val.len() as u64) < self.capacity() {
            new_len = new_val.len() as u64;
        }

        *self.len = 0;
        unsafe {
            copy_nonoverlapping(new_val.as_ptr(), self.buf.as_mut_ptr(), new_len as usize);
        }
        *self.len = new_len;
    }

    /// Returns the current contents of the buf
    pub fn get(&self) -> &[u8] {
        &self.buf[..*self.len as usize]
    }
}

impl<'a> SpRead<'a> for GenericBuf {
    fn inner_from_bytes(
        input: &'a [u8],
        _is_input_le: bool,
        _count: Option<usize>,
    ) -> Result<(&'a [u8], Self), SpError>
    where
        Self: 'a + Sized,
    {
        if input.len() < std::mem::size_of::<u64>() + std::mem::size_of::<u64>() {
            return Err(SpError::NotEnoughBytes);
        }
        let (val, rest) = input.split_at(std::mem::size_of::<u64>());
        let capacity = unsafe { &mut *(val.as_ptr() as *const u64 as *mut u64) };
        let (val, rest) = rest.split_at(std::mem::size_of::<u64>());
        let len = unsafe { &mut *(val.as_ptr() as *const u64 as *mut u64) };

        if *capacity > rest.len() as u64 || *len > *capacity {
            return Err(SpError::NotEnoughBytes);
        }

        let (val, rest) = rest.split_at(*capacity as usize);
        let buf = unsafe {
            std::slice::from_raw_parts_mut(val.as_ptr() as *const u8 as *mut u8, *capacity as usize)
        };
        Ok((rest, Self { capacity, len, buf }))
    }

    fn from_bytes(input: &'a [u8]) -> Result<(&'a [u8], Self), SpError>
    where
        Self: 'a + Sized,
    {
        Self::inner_from_bytes(input, true, None)
    }
}

impl<'a> SpRead<'a> for StatNum {
    fn inner_from_bytes(
        input: &'a [u8],
        _is_input_le: bool,
        _count: Option<usize>,
    ) -> Result<(&'a [u8], Self), SpError>
    where
        Self: 'a + Sized,
    {
        if input.len() < std::mem::size_of::<u64>() {
            return Err(SpError::NotEnoughBytes);
        }
        let (typ_bytes, rest) = input.split_at(std::mem::size_of::<u64>());
        let val = unsafe { &mut *(typ_bytes.as_ptr() as *const u64 as *mut u64) };

        Ok((rest, Self { val }))
    }

    fn from_bytes(input: &'a [u8]) -> Result<(&'a [u8], Self), SpError>
    where
        Self: 'a + Sized,
    {
        Self::inner_from_bytes(input, true, None)
    }
}

impl<'a> SpRead<'a> for StatStr {
    fn inner_from_bytes(
        input: &'a [u8],
        _is_input_le: bool,
        _count: Option<usize>,
    ) -> Result<(&'a [u8], Self), SpError>
    where
        Self: 'a + Sized,
    {
        if input.len() < std::mem::size_of::<AtomicU8>() {
            return Err(SpError::NotEnoughBytes);
        }
        let (typ_bytes, rest) = input.split_at(std::mem::size_of::<AtomicU8>());
        let lock = unsafe { &mut *(typ_bytes.as_ptr() as *const AtomicU8 as *mut AtomicU8) };
        let r = GenericBuf::from_bytes(rest)?;

        Ok((r.0, Self { lock, val: r.1 }))
    }

    fn from_bytes(input: &'a [u8]) -> Result<(&'a [u8], Self), SpError>
    where
        Self: 'a + Sized,
    {
        Self::inner_from_bytes(input, true, None)
    }
}

impl<'a> SpRead<'a> for StatBytes {
    fn inner_from_bytes(
        input: &'a [u8],
        _is_input_le: bool,
        _count: Option<usize>,
    ) -> Result<(&'a [u8], Self), SpError>
    where
        Self: 'a + Sized,
    {
        if input.len() < std::mem::size_of::<AtomicU8>() {
            return Err(SpError::NotEnoughBytes);
        }
        let (typ_bytes, rest) = input.split_at(std::mem::size_of::<AtomicU8>());
        let lock = unsafe { &mut *(typ_bytes.as_ptr() as *const AtomicU8 as *mut AtomicU8) };
        let r = GenericBuf::from_bytes(rest)?;

        Ok((r.0, Self { lock, val: r.1 }))
    }

    fn from_bytes(input: &'a [u8]) -> Result<(&'a [u8], Self), SpError>
    where
        Self: 'a + Sized,
    {
        Self::inner_from_bytes(input, true, None)
    }
}

pub struct LockGuard<'a, T>
where
    T: 'a,
{
    lock: &'a mut AtomicU8,
    val: T,
}

use std::ops::Deref;
impl<'t, T> LockGuard<'t, T> {
    pub fn new(lock: &'t mut AtomicU8, val: T) -> Self
    where
        T: 't,
    {
        Self { lock, val }
    }
}

impl<'t, T> Drop for LockGuard<'t, T> {
    fn drop(&mut self) {
        release(self.lock);
    }
}

impl<'t, T> Deref for LockGuard<'t, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.val
    }
}
