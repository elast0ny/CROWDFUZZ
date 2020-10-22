use simple_parse::*;
use std::ptr::copy_nonoverlapping;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::*;

pub fn update_average(cur_avg: &mut u64, new_val: u64, val_num: u64) {
    let cur_val = *cur_avg;
    *cur_avg = if cur_val > new_val {
        cur_val - ((cur_val - new_val) / val_num)
    } else {
        cur_val + ((new_val - cur_val) / val_num)
    };
}

/// Removes known prefixes and postfixes
pub fn strip_tag_hints(tag: &str) -> (&str, (Option<&'static str>, Option<&'static str>)) {
    let (res_tag, prefix) = strip_tag_prefix(tag);
    let (res_tag, postfix) = strip_tag_postfix(res_tag);

    (res_tag, (prefix, postfix))
}

/// Removes known prefixes from a stat tag if present
pub fn strip_tag_prefix(tag: &str) -> (&str, Option<&'static str>) {
    let tag_len = tag.len();

    for val in TAG_PREFIXES {
        let val_len = val.len();

        if tag_len < val_len {
            continue;
        }

        if tag.starts_with(*val) {
            return (&tag[val_len..], Some(*val));
        }
    }

    (tag, None)
}
/// Removes known postfixes from a stat tag if present
pub fn strip_tag_postfix(tag: &str) -> (&str, Option<&'static str>) {
    let tag_len = tag.len();

    for postfix in TAG_POSTFIXES {
        let postfix_len = postfix.len();

        if tag_len < postfix_len {
            continue;
        }

        if &tag[tag_len - postfix_len..] == *postfix {
            return (&tag[..tag_len - postfix_len], Some(*postfix));
        }
    }

    (tag, None)
}

pub fn pretty_num(dst: &mut String, mut val: u64, type_hints: (Option<&'static str>, Option<&'static str>)) {
    use std::fmt::Write;

    let mut generated_str = false;

    const US_IN_MS: u64 = 1000;
    const US_IN_S: u64 = 1000 * US_IN_MS;
    const US_IN_M: u64 = 60 * US_IN_S;
    const US_IN_H: u64 = 60 * US_IN_M;

    if let Some(postfix) = type_hints.1 {

        val = match postfix {
            TAG_POSTFIX_HEX => {
                let _ =write!(dst, "0x{:X}", val);
                return;
            },
            // Convert time number to US
            TAG_POSTFIX_MS => val * US_IN_MS,
            TAG_POSTFIX_SEC | TAG_POSTFIX_EPOCHS => val * US_IN_S,
            TAG_POSTFIX_MIN => val * US_IN_M,
            TAG_POSTFIX_HOUR => val * US_IN_H,
            TAG_POSTFIX_US => val,
            // Any other postfix dont apply to numbers
            _ => {
                let _ =write!(dst, "{}?", val);
                return;
            },
        };
        
        // Attempt to write "long" timescales
        if val > US_IN_H {
            let _ = write!(dst, "{}h", val / US_IN_H);
            val %= US_IN_H;
            generated_str = true;
        }
        if val > US_IN_M {
            let _ = write!(dst, "{}m", val / US_IN_M);
            val %= US_IN_M;
            generated_str = true;
        }
        if val > US_IN_S {
            let _ = write!(dst, "{}", val / US_IN_S);
            val %= US_IN_S;
            if val > US_IN_MS {
                let _ = write!(dst, ".{:03}s", val / US_IN_MS);
            } else {
                let _ = write!(dst, "s");
            }
            generated_str = true;
        }
    
        // Write smaller time scales
        if !generated_str {
            if val > US_IN_MS {
                let _ = write!(dst, "{}ms", val / US_IN_MS);
            } else if val > 0 {
                let _ = write!(dst, "{}us", val);
            } else {
                dst.push('0');
            }

            generated_str = true;
        }
    }

    if !generated_str {
        let _ = write!(dst, "{}", val);
        return;
    }
}

pub fn pretty_str(dst: &mut String, mut val: &str, type_hints: (Option<&'static str>, Option<&'static str>)) {
    use std::fmt::Write;

    if let Some(postfix) = type_hints.1 {
        // Strip windows path grossness
        if postfix == TAG_POSTFIX_PATH && val.starts_with("\\\\?\\") {
            val = &val[4..];
        }
    }
    let _ = write!(dst, "{}", val);
}

pub fn pretty_bytes(dst: &mut String, val: &[u8], type_hints: (Option<&'static str>, Option<&'static str>)) {
    use std::fmt::Write;
    let mut wrote = false;
    if let Some(postfix) = type_hints.1 {
        // Strip windows path grossness
        if postfix == TAG_POSTFIX_HEX {
            for b in val {
                let _ = write!(dst, "{:02X}", *b);
            }
            wrote = true;
        }
    }

    if !wrote {
        let _ = write!(dst, "{:02X?}", val);
    }
}

/// Crappy busy loop over a u8
pub(crate) fn acquire(lock: &mut AtomicU8) {
    loop {
        // If currently 0, set to 1
        match lock.compare_exchange(0, 1, Ordering::Acquire, Ordering::Acquire) {
            Ok(_) => break,
            _ => continue,
        };
    }
}
/// Sets the lock to its unlocked state
pub(crate) fn release(lock: &mut AtomicU8) {
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
    ) -> std::result::Result<(&'a [u8], Self), SpError>
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

    fn from_bytes(input: &'a [u8]) -> std::result::Result<(&'a [u8], Self), SpError>
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
    ) -> std::result::Result<(&'a [u8], Self), SpError>
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

    fn from_bytes(input: &'a [u8]) -> std::result::Result<(&'a [u8], Self), SpError>
    where
        Self: 'a + Sized,
    {
        Self::inner_from_bytes(input, true, None)
    }
}
impl std::fmt::Debug for StatNum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:X}", self.val)
    }
}

impl<'a> SpRead<'a> for StatStr {
    fn inner_from_bytes(
        input: &'a [u8],
        _is_input_le: bool,
        _count: Option<usize>,
    ) -> std::result::Result<(&'a [u8], Self), SpError>
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

    fn from_bytes(input: &'a [u8]) -> std::result::Result<(&'a [u8], Self), SpError>
    where
        Self: 'a + Sized,
    {
        Self::inner_from_bytes(input, true, None)
    }
}
impl std::fmt::Debug for StatStr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}/{}] '{}'", self.val.len, self.val.capacity(), unsafe{std::str::from_utf8_unchecked(self.val.get())})
    }
}

impl<'a> SpRead<'a> for StatBytes {
    fn inner_from_bytes(
        input: &'a [u8],
        _is_input_le: bool,
        _count: Option<usize>,
    ) -> std::result::Result<(&'a [u8], Self), SpError>
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

    fn from_bytes(input: &'a [u8]) -> std::result::Result<(&'a [u8], Self), SpError>
    where
        Self: 'a + Sized,
    {
        Self::inner_from_bytes(input, true, None)
    }
}
impl std::fmt::Debug for StatBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}/{}] {:X?}", self.val.len, self.val.capacity(), self.val.get())
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
