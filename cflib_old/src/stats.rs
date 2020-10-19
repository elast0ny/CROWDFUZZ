use crate::*;
use std::mem::size_of;

/// Stat tag prefixes to give hints to UIs
pub const TAG_PREFIX: &[&str] = &[TAG_PREFIX_TOTAL_STR, TAG_PREFIX_AVERAGE_STR];

/// Specifies the data content type of string stats
pub const STR_POSTFIX: &[&str] = &[STR_POSTFIX_DIR_STR];

/// Specifies the data content type of number stats
pub const NUM_POSTFIX: &[&str] = &[
    NUM_POSTFIX_EPOCHS_STR,
    NUM_POSTFIX_US_STR,
    NUM_POSTFIX_MS_STR,
    NUM_POSTFIX_SEC_STR,
    NUM_POSTFIX_MIN_STR,
    NUM_POSTFIX_HOUR_STR,
];

/// Sepcifies the data content type of byte stats
pub const BYTES_POSTFIX: &[&str] = &[BYTES_POSTFIX_HEX_STR];

/// Used to request new stat space from the core. Dynamic type
/// require a max length for the stat value.
#[derive(Debug)]
pub enum NewStat {
    #[doc(hidden)]
    Bytes(u16),
    Str(u16),
    Number,
}

impl NewStat {
    pub fn from_stat_type(stat_type: StatType, max_len: u16) -> Self {
        let new_stat = match stat_type as _ {
            STAT_BYTES => NewStat::Bytes(max_len),
            STAT_STR => NewStat::Str(max_len),
            STAT_NUMBER => NewStat::Number,
            _ => panic!("Unknown stat type {} (max_len {})", stat_type, max_len),
        };

        if max_len != new_stat.max_len() {
            panic!(
                "Requested max stat length {} doesnt match the stat {:?}(max_len {})",
                max_len,
                new_stat,
                new_stat.max_len()
            );
        }

        new_stat
    }
    pub fn header_len(&self) -> usize {
        match &self {
            &NewStat::Bytes(_) | &NewStat::Str(_) => size_of::<StatHeaderDyn>(),
            _ => size_of::<StatHeader>(),
        }
    }
    pub fn max_len(&self) -> u16 {
        (match &self {
            NewStat::Bytes(v) => *v as usize,
            NewStat::Str(v) => *v as usize,
            NewStat::Number => size_of::<u64>(),
        }) as u16
    }
    pub fn to_id(&self) -> StatType {
        match &self {
            NewStat::Bytes(_) => STAT_BYTES as _,
            NewStat::Str(_) => STAT_STR as _,
            NewStat::Number => STAT_NUMBER as _,
        }
    }
}

use std::ptr::copy_nonoverlapping;
use std::sync::atomic::{AtomicU16, Ordering};

/// Safely reads the content of a dynamicaly sized stat buffer
/// WARNING : dst must point to an allocation of at least max_data_len bytes.
/// Returns the number of bytes written
/// # Safety
/// This function is unsafe as is dereferences/wrties to arbitrary addresses
pub unsafe fn copy_dyn_stat(dst: *mut u8, src: *mut u8) -> usize {
    let atom_cur_len: &mut AtomicU16 = &mut *(src as *mut AtomicU16);
    let mut cur_len;
    // Busy loop until we set the length to 0
    loop {
        cur_len = *(src as *mut u16);
        // Set length to 0 if not already 0
        match atom_cur_len.compare_exchange(cur_len, 0, Ordering::Acquire, Ordering::Acquire) {
            Ok(_) => break,
            _ => continue,
        };
    }
    copy_nonoverlapping(src.add(size_of::<u16>()), dst, cur_len as usize);
    atom_cur_len.store(cur_len, Ordering::Release);
    cur_len as usize
}

/// Safely overwrites the content of a dynamicaly sized stat buffer
/// # Safety
/// This function is unsafe as is dereferences an arbitrary address
pub unsafe fn update_dyn_stat<B: AsRef<[u8]>>(dst: *mut u8, data: B) {
    let mut data = data.as_ref();
    if data.is_empty() {
        data = &[0];
    }
    let src_len = data.len();
    let src = data.as_ptr();

    let atom_cur_len: &mut AtomicU16 = &mut *(dst as *mut AtomicU16);
    let mut cur_len;
    // Busy loop until we set the length to 0
    loop {
        cur_len = *(dst as *mut u16);
        // Set length to 0 if not already 0
        match atom_cur_len.compare_exchange(cur_len, 0, Ordering::Acquire, Ordering::Acquire) {
            Ok(_) => break,
            _ => continue,
        };
    }
    copy_nonoverlapping(src, dst.add(size_of::<u16>()), src_len);
    atom_cur_len.store(src_len as u16, Ordering::Release);
}
