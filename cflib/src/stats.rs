use std::mem::size_of;
use std::ptr::{copy_nonoverlapping};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::*;

pub static STR_POSTFIX: &[&str] = &[
    "_dir",
];

/// Specifies the data content type of number stats
pub static NUM_POSTFIX: &[&str] = &[
    "_epochs", // Since epoch
    "_us",
    "_ms",
    "_s",
    "_m",
    "_h",
];

/// Sepcifies the data content type of byte stats
pub static BYTES_POSTFIX: &[&str] = &[
    "_hex",
];

/// Used to request new stat space from the core. Dynamic type
/// require a max length for the stat value.
#[derive(Debug)]
pub enum NewStat {
    #[doc(hidden)]
    Bytes(u16),
    Str(u16),
    USize,
    ISize,
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
}

impl NewStat {
    pub fn from_stat_type(stat_type: StatType, max_len: u16) -> Self {
        let new_stat = match stat_type {
            STAT_BYTES => NewStat::Bytes(max_len),
            STAT_STR => NewStat::Str(max_len),
            STAT_USIZE => NewStat::USize,
            STAT_ISIZE => NewStat::ISize,
            STAT_U8 => NewStat::U8,
            STAT_U16 => NewStat::U16,
            STAT_U32 => NewStat::U32,
            STAT_U64 => NewStat::U64,
            STAT_I8 => NewStat::I8,
            STAT_I16 => NewStat::I16,
            STAT_I32 => NewStat::I32,
            STAT_I64 => NewStat::I64,
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
            &NewStat::Bytes(v) => *v as usize,
            &NewStat::Str(v) => *v as usize,
            &NewStat::USize => size_of::<usize>(),
            &NewStat::ISize => size_of::<isize>(),
            &NewStat::U8 => size_of::<u8>(),
            &NewStat::U16 => size_of::<u16>(),
            &NewStat::U32 => size_of::<u32>(),
            &NewStat::U64 => size_of::<u64>(),
            &NewStat::I8 => size_of::<i8>(),
            &NewStat::I16 => size_of::<i16>(),
            &NewStat::I32 => size_of::<i32>(),
            &NewStat::I64 => size_of::<i64>(),
        }) as u16
    }
    pub fn to_id(&self) -> StatType {
        match &self {
            &NewStat::Bytes(_) => STAT_BYTES,
            &NewStat::Str(_) => STAT_STR,
            &NewStat::USize => STAT_USIZE,
            &NewStat::ISize => STAT_ISIZE,
            &NewStat::U8 => STAT_U8,
            &NewStat::U16 => STAT_U16,
            &NewStat::U32 => STAT_U32,
            &NewStat::U64 => STAT_U64,
            &NewStat::I8 => STAT_I8,
            &NewStat::I16 => STAT_I16,
            &NewStat::I32 => STAT_I32,
            &NewStat::I64 => STAT_I64,
        }
    }
}

/* ---------------------------- */
/* For front end writers bellow */
/* ---------------------------- */

pub fn stat_header_size(some_val: StatType) -> u16 {
    return match some_val {
        STAT_BYTES | STAT_STR => size_of::<StatHeaderDyn>(),
        _ => size_of::<StatHeader>(),
    } as u16;
}

pub fn stat_static_data_len(some_val: StatType) -> Option<u16> {
    match some_val {
        STAT_NEWCOMPONENT => Some(0),
        STAT_BYTES => None,
        STAT_STR => None,
        STAT_USIZE => Some(size_of::<usize>() as u16),
        STAT_ISIZE => Some(size_of::<isize>() as u16),
        STAT_U8 => Some(size_of::<u8>() as u16),
        STAT_U16 => Some(size_of::<u16>() as u16),
        STAT_U32 => Some(size_of::<u32>() as u16),
        STAT_U64 => Some(size_of::<u64>() as u16),
        STAT_I8 => Some(size_of::<i8>() as u16),
        STAT_I16 => Some(size_of::<i16>() as u16),
        STAT_I32 => Some(size_of::<i32>() as u16),
        STAT_I64 => Some(size_of::<i64>() as u16),
        _ => panic!("Invalid StatType given : {}...", some_val),
    }
}

/// Concrete value that a stat can point to
#[derive(Debug)]
pub enum StatVal {
    Component(String),
    Bytes(Vec<u8>),
    Str(String),
    USize(usize),
    ISize(isize),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
}

impl StatVal {
    pub fn is_equal(&self, src: &StatRef) -> bool {
        unsafe{
        match self {
            StatVal::Component(_) => true,
            StatVal::Bytes(dst) => {
                if *(src.data_ptr as *mut u16) as usize != dst.len() {
                    false
                } else {
                    let bytes = std::slice::from_raw_parts(src.data_ptr.add(size_of::<u16>()), dst.len());
                    dst == &bytes
                }
            },
            StatVal::Str(dst) => {
                if *(src.data_ptr as *mut u16) as usize != dst.len() {
                    false
                } else {
                    let bytes = std::slice::from_raw_parts(src.data_ptr.add(size_of::<u16>()), dst.len());
                    &dst.as_bytes() == &bytes
                }
            },
            StatVal::USize(v) => {*v == *(src.data_ptr as *mut usize)},
            StatVal::ISize(v) => {*v == *(src.data_ptr as *mut isize)},
            StatVal::U8(v) => {*v == *(src.data_ptr as *mut u8)},
            StatVal::U16(v) => {*v == *(src.data_ptr as *mut u16)},
            StatVal::U32(v) => {*v == *(src.data_ptr as *mut u32)},
            StatVal::U64(v) => {*v == *(src.data_ptr as *mut u64)},
            StatVal::I8(v) => {*v == *(src.data_ptr as *mut i8)},
            StatVal::I16(v) => {*v == *(src.data_ptr as *mut i16)},
            StatVal::I32(v) => {*v == *(src.data_ptr as *mut i32)},
            StatVal::I64(v) => {*v == *(src.data_ptr as *mut i64)},
        }
        }

    }
    pub fn update(&mut self, src: &StatRef) {
        unsafe {
        match self {
            StatVal::Component(_) => {},
            StatVal::Bytes(dst) => {
                let cur_len = copy_dyn_stat(dst.as_mut_ptr(), src.data_ptr);
                dst.set_len(cur_len);
            },
            StatVal::Str(dst) => {
                let dst = dst.as_mut_vec();
                let cur_len = copy_dyn_stat(dst.as_mut_ptr(), src.data_ptr);
                dst.set_len(cur_len);
            },
            StatVal::USize(v) => {*v = *(src.data_ptr as *mut usize)},
            StatVal::ISize(v) => {*v = *(src.data_ptr as *mut isize)},
            StatVal::U8(v) => {*v = *(src.data_ptr as *mut u8)},
            StatVal::U16(v) => {*v = *(src.data_ptr as *mut u16)},
            StatVal::U32(v) => {*v = *(src.data_ptr as *mut u32)},
            StatVal::U64(v) => {*v = *(src.data_ptr as *mut u64)},
            StatVal::I8(v) => {*v = *(src.data_ptr as *mut i8)},
            StatVal::I16(v) => {*v = *(src.data_ptr as *mut i16)},
            StatVal::I32(v) => {*v = *(src.data_ptr as *mut i32)},
            StatVal::I64(v) => {*v = *(src.data_ptr as *mut i64)},
        }
        }
    }
    pub fn write_str(&self, dst: &mut String) {
        use std::fmt::Write;
        dst.clear();
        let _ = match self {
            StatVal::Component(v) => write!(dst, "{}", v),
            StatVal::Bytes(v) => {
                for byte in v {
                    let _ = write!(dst, "{:02X}", byte);
                }
                Ok(())
            },
            StatVal::Str(v) => write!(dst, "{}", v),
            StatVal::USize(v) => write!(dst, "{}", v),
            StatVal::ISize(v) => write!(dst, "{}", v),
            StatVal::U8(v) => write!(dst, "{}", v),
            StatVal::U16(v) => write!(dst, "{}", v),
            StatVal::U32(v) => write!(dst, "{}", v),
            StatVal::U64(v) => write!(dst, "{}", v),
            StatVal::I8(v) => write!(dst, "{}", v),
            StatVal::I16(v) => write!(dst, "{}", v),
            StatVal::I32(v) => write!(dst, "{}", v),
            StatVal::I64(v) => write!(dst, "{}", v),
        };
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            StatVal::Component(v) | StatVal::Str(v) => Some(v.as_str()),
            _ => None,
        }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            StatVal::Bytes(v) => Some(&v),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            StatVal::U8(v) => Some(*v as u64),
            StatVal::U16(v) => Some(*v as u64),
            StatVal::U32(v) => Some(*v as u64),
            StatVal::U64(v) => Some(*v as u64),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            StatVal::I8(v) => Some(*v as i64),
            StatVal::I16(v) => Some(*v as i64),
            StatVal::I32(v) => Some(*v as i64),
            StatVal::I64(v) => Some(*v as i64),
            _ => None,
        }
    }
}

use std::fmt;
impl fmt::Display for StatVal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut res = String::new();
        self.write_str(&mut res);
        write!(f, "{}", res.as_str())
    }
}

/// Holds valid pointers into a stat field in shared memory
pub struct StatRef {
    t: StatType,
    tag_len: u16,
    tag_ptr: *mut u8,
    max_data_len: u16,
    data_ptr: *mut u8,
}
impl StatRef {
    /// Prases a new stat from a raw pointer
    pub fn from_base_ptr(
        base_ptr: *mut u8,
        max_bytes: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut shmem_idx: usize = 0;

        // Get the stat header
        let mut max_data_len;
        let header: &StatHeader = match stat_static_data_len(unsafe { *(base_ptr as *mut _) }) {
            Some(l) => {
                max_data_len = l;
                shmem_idx += size_of::<StatHeader>();
                unsafe { &*(base_ptr as *const _) }
            }
            None => {
                let dyn_header: &mut StatHeaderDyn = unsafe { &mut *(base_ptr as *mut _) };
                max_data_len = dyn_header.data_len;
                shmem_idx += size_of::<StatHeaderDyn>();
                &dyn_header.header
            }
        };
        // Make sure we can read the header values
        if shmem_idx >= max_bytes {
            return Err(From::from(
                "Not enough bytes left for a stat header".to_owned(),
            ));
        }

        let tag_ptr = unsafe { base_ptr.add(shmem_idx) as *mut _ };
        shmem_idx += header.tag_len as usize;
        // enough bytes left for the tag
        if shmem_idx >= max_bytes {
            return Err(From::from(
                "Not enough bytes left for the stat tag".to_owned(),
            ));
        }

        let data_ptr;
        if header.stat_type == STAT_NEWCOMPONENT {
            max_data_len = header.tag_len;
            data_ptr = tag_ptr;
        } else {
            data_ptr = unsafe { base_ptr.add(shmem_idx) as *mut _ };
            shmem_idx += max_data_len as usize;
        }
        
        if shmem_idx > max_bytes {
            return Err(From::from(
                "Not enough bytes left for the stat data".to_owned(),
            ));
        }

        Ok(Self {
            t: header.stat_type,
            tag_len: header.tag_len,
            tag_ptr,
            max_data_len,
            data_ptr,
        })
    }
    /// The total space used in the stats file for this stat
    pub fn mem_len(&self) -> usize {
        let max_data_len = match stat_static_data_len(self.t) {
            Some(l) => l as usize,
            None => {
                // Dynamic size field + data size
                size_of::<u16>() + self.max_data_len as usize
            }
        };
        size_of::<StatHeader>() + self.tag_len as usize + max_data_len
    }
    /// Returns a reference to the stat tag
    pub fn get_tag(&self) -> &str {
        //println!("{:p}[{}] = ", self.tag_ptr, self.tag_len);
        let tag = unsafe {
            std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                self.tag_ptr,
                self.tag_len as usize,
            ))
        };
        //println!("{}", tag);
        tag
    }

    /// Returns a copy of the value. The potential allocation will always
    /// be big enough to hold the biggest value of the current stat
    pub fn to_owned(&self) -> StatVal {
        unsafe {
            match self.t {
                STAT_NEWCOMPONENT => {
                    let mut res = Vec::with_capacity(self.tag_len as usize);
                    copy_nonoverlapping(self.tag_ptr, res.as_mut_ptr(), self.tag_len as usize);
                    res.set_len(self.tag_len as usize);
                    StatVal::Component(String::from_utf8_unchecked(res))
                },
                STAT_BYTES => {
                    let mut res = Vec::with_capacity(self.max_data_len as usize);
                    let cur_len = copy_dyn_stat(res.as_mut_ptr(), self.data_ptr);
                    res.set_len(cur_len);
                    StatVal::Bytes(res)
                },
                STAT_STR => {
                    let mut res = Vec::with_capacity(self.max_data_len as usize);
                    let cur_len = copy_dyn_stat(res.as_mut_ptr(), self.data_ptr);
                    res.set_len(cur_len);
                    StatVal::Str(String::from_utf8_unchecked(res))
                },
                STAT_USIZE => StatVal::USize(*(self.data_ptr as *mut usize)),
                STAT_ISIZE => StatVal::ISize(*(self.data_ptr as *mut isize)),
                STAT_U8 => StatVal::U8(*(self.data_ptr as *mut u8)),
                STAT_U16 => StatVal::U16(*(self.data_ptr as *mut u16)),
                STAT_U32 => StatVal::U32(*(self.data_ptr as *mut u32)),
                STAT_U64 => StatVal::U64(*(self.data_ptr as *mut u64)),
                STAT_I8 => StatVal::I8(*(self.data_ptr as *mut i8)),
                STAT_I16 => StatVal::I16(*(self.data_ptr as *mut i16)),
                STAT_I32 => StatVal::I32(*(self.data_ptr as *mut i32)),
                STAT_I64 => StatVal::I64(*(self.data_ptr as *mut i64)),
                _ => panic!("Invalid StatType given..."),
            }
        }
    }

    pub fn is_component(&self) -> bool {
        self.t == STAT_NEWCOMPONENT
    }
}

pub fn strip_known_postfix(tag: &str) -> (&str, Option<&'static str>) {
    let tag_len = tag.len();
    
    // Numbers
    for postfix in NUM_POSTFIX {
        let postfix_len = postfix.len();

        if tag_len < postfix_len {
            continue;
        }

        if &tag[tag_len - postfix_len..] == *postfix {
            return (&tag[..tag_len - postfix_len], Some(*postfix));
        }
    }
    // Strings
    for postfix in STR_POSTFIX {
        let postfix_len = postfix.len();

        if tag_len < postfix_len {
            continue;
        }

        if &tag[tag_len - postfix_len..] == *postfix {
            return (&tag[..tag_len - postfix_len], Some(*postfix));
        }
    }
    // Bytes
    for postfix in BYTES_POSTFIX {
        let postfix_len = postfix.len();

        if tag_len < postfix_len {
            continue;
        }

        if &tag[tag_len - postfix_len..] == *postfix {
            return (&tag[..tag_len - postfix_len], Some(*postfix));
        }
    }

    return (tag, None);
}

const MS_IN_US: u64 = 1000;
const S_IN_US: u64 = 1000 * MS_IN_US;
const M_IN_US: u64 = 60 * S_IN_US;
const H_IN_US: u64 = 60 * M_IN_US;

// Caller must clear the string before calling
fn format_duration(dst: &mut String, mut val: u64, unit: &str) {
    use std::fmt::Write;
    // conver to us
    val *= match unit {
        "ms" => MS_IN_US,
        "s" => S_IN_US,
        "m" => M_IN_US,
        "h" => H_IN_US,
        _ => 1,
    };

    if val > H_IN_US {
        let _ = write!(dst, "{}h{}m{}s", val / H_IN_US, (val % H_IN_US) / M_IN_US, (val % M_IN_US) / S_IN_US);
    } else if val > M_IN_US {
        let _ = write!(dst, "{}m{}s", val / M_IN_US, (val % M_IN_US) / S_IN_US);
    } else if val > S_IN_US {
        let _ = write!(dst, "{}.{}s", val / S_IN_US, (val % S_IN_US) / MS_IN_US);
    } else if val > MS_IN_US {
        let _ = write!(dst, "{}.{}ms", val / MS_IN_US, (val % MS_IN_US));
    } else {
        let _ = write!(dst, "{}us", val);
    }
}

pub fn write_pretty_stat(dst: &mut String, src: &StatVal, tag_postfix: &str) {
    use std::fmt::Write;

    let mut is_negative = false;
    let num = match src.as_u64() {
        Some(v) => Some(v),
        None => match src.as_i64() {
            Some(v) => {
                is_negative = true;
                Some(v.abs() as u64)
            },
            None => None,
        },
    };

    if let Some(num) = num {
        let unit = match tag_postfix.rfind("_") {
            Some(idx) => &tag_postfix[idx+1..],
            None => "us",
        };
        
        dst.clear();
        if is_negative {
            dst.push('-');
        }

        if tag_postfix.starts_with("_time") {
            format_duration(dst, SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - num, "s");
        } else {
            format_duration(dst, num, unit);
        }
        
    } else if let Some(mut s) = src.as_str() {
        dst.clear();
        if tag_postfix == "_dir" {
            if s.starts_with("\\\\?\\") {
                s = &s[4..];
            }
        }
        let _ = write!(dst, "{}", s);
    } else if let Some(b) = src.as_bytes() {
        dst.clear();
        if tag_postfix == "_hex" {
            for byte in b {
                let _ = write!(dst, "{:02X}", byte);
            }
        } else {
            let _ = write!(dst, "{:?}", b);
        }
    }
}

/// Copies the current value into dst. dst must point to an allocation
/// of at least max_data_len bytes.
/// Returns the number of bytes written
unsafe fn copy_dyn_stat(dst: *mut u8, src: *mut u8) -> usize {
    
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

/// Helper to write dynamically sized stats to memory
pub fn update_dyn_stat<B: AsRef<[u8]>>(dst: *mut u8, data: B) {

    let mut data = data.as_ref();
    if data.len() == 0 {
        data = &[0];
    }
    let src_len = data.len();
    let src = data.as_ptr();

    unsafe {
        let atom_cur_len: &mut AtomicU16 = &mut *(dst as *mut AtomicU16);
        let mut cur_len;
        // Busy loop until we set the length to 0
        loop {
            cur_len = *(dst as *mut u16);
            // Set length to 0 if not already 0
            match atom_cur_len.compare_exchange(cur_len, 0, Ordering::Acquire, Ordering::Acquire) {
                Ok(_)  => break,
                _ => continue,
            };
        }
        copy_nonoverlapping(src, dst.add(size_of::<u16>()), src_len);
        atom_cur_len.store(src_len as u16, Ordering::Release);
    }
}

