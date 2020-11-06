use ::simple_parse::*;
use std::ptr::copy_nonoverlapping;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::*;

pub const US_TO_NS: u64 = 1_000; //microseconds
pub const MS_TO_NS: u64 = 1_000_000; // milliseconds
pub const S_TO_NS: u64 = 1_000_000_000; // seconds
pub const M_TO_NS: u64 = 60 * S_TO_NS;
pub const H_TO_NS: u64 = 60 * M_TO_NS;

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

pub fn pretty_num(
    dst: &mut String,
    mut val: u64,
    type_hints: (Option<&'static str>, Option<&'static str>),
) {
    use std::fmt::Write;

    let mut generated_str = false;

    if let Some(postfix) = type_hints.1 {
        val = match postfix {
            TAG_POSTFIX_HEX => {
                let _ = write!(dst, "0x{:X}", val);
                return;
            }
            TAG_POSTFIX_RESULT => {
                let _ = write!(dst, "{}", val);
                return;
            }
            // Convert time number to ns
            TAG_POSTFIX_NS => val,
            TAG_POSTFIX_US => val * US_TO_NS,
            TAG_POSTFIX_MS => val * MS_TO_NS,
            TAG_POSTFIX_SEC | TAG_POSTFIX_EPOCHS => val * S_TO_NS,
            TAG_POSTFIX_MIN => val * M_TO_NS,
            TAG_POSTFIX_HOUR => val * H_TO_NS,
            // Any other postfix dont apply to numbers
            _ => {
                let _ = write!(dst, "{}?", val);
                return;
            }
        };

        // Attempt to write "long" timescales
        if val > H_TO_NS {
            let _ = write!(dst, "{}h", val / H_TO_NS);
            val %= H_TO_NS;
            generated_str = true;
        }
        if val > M_TO_NS {
            let _ = write!(dst, "{}m", val / M_TO_NS);
            val %= M_TO_NS;
            generated_str = true;
        }
        if val > S_TO_NS {
            let _ = write!(dst, "{}", val / S_TO_NS);
            val %= S_TO_NS;
            if val > MS_TO_NS {
                let _ = write!(dst, ".{:03}s", val / MS_TO_NS);
            } else {
                dst.push('s');
            }
            generated_str = true;
        }

        // Write smaller time scales
        if !generated_str {
            if val > MS_TO_NS {
                let _ = write!(dst, "{} ms", val / MS_TO_NS);
            } else if val > 2 * US_TO_NS {
                let _ = write!(dst, "{} us", val / US_TO_NS);
            } else if val > 0 {
                let _ = write!(dst, "{}.{:03} us", val / US_TO_NS, val % US_TO_NS);
            } else {
                dst.push_str("<1 ns");
            }
            generated_str = true;
        }
    }

    if !generated_str {
        let _ = write!(dst, "{}", val);
        return;
    }
}

pub fn pretty_str(
    dst: &mut String,
    mut val: &str,
    type_hints: (Option<&'static str>, Option<&'static str>),
) {
    if let Some(postfix) = type_hints.1 {
        // Strip windows path grossness
        if postfix == TAG_POSTFIX_PATH && val.starts_with("\\\\?\\") {
            val = &val[4..];
        }
    }
    dst.push_str(val);
}

pub fn pretty_bytes(
    dst: &mut String,
    val: &[u8],
    type_hints: (Option<&'static str>, Option<&'static str>),
) {
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

#[derive(SpReadRawMut, Debug)]
pub(crate) struct GenericBuf<'b> {
    capacity: &'b mut u64,
    len: &'b mut u64,
    #[sp(count="capacity")]
    buf: &'b mut [u8],
}
impl<'b> GenericBuf<'b> {
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

impl<'b> std::fmt::Debug for StatNum<'b> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:X}", self.val)
    }
}

impl<'b> std::fmt::Debug for StatStr<'b> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}/{}] '{}'",
            self.val.len,
            self.val.capacity(),
            unsafe { std::str::from_utf8_unchecked(self.val.get()) }
        )
    }
}

impl<'b> std::fmt::Debug for StatBytes<'b> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}/{}] {:X?}",
            self.val.len,
            self.val.capacity(),
            self.val.get()
        )
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
