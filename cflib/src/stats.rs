use ::std::mem::size_of;
use std::ptr::null_mut;

use crate::*;

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

/// Concrete value that a statistic can hold
#[derive(Debug)]
pub enum StatVal {
    Component(&'static str),
    Bytes(&'static [u8]),
    Str(&'static str),
    USize(&'static usize),
    ISize(&'static isize),
    U8(&'static u8),
    U16(&'static u16),
    U32(&'static u32),
    U64(&'static u64),
    I8(&'static i8),
    I16(&'static i16),
    I32(&'static i32),
    I64(&'static i64),
}
/// Holds references to an existing stat
pub struct StatRef {
    t: StatType,
    tag_len: u16,
    tag_ptr: *mut u8,
    max_data_len: *mut u16,
    data_ptr: *mut u8,
    str_repr: String,
}
impl StatRef {
    /// Prases a new stat from a raw pointer
    pub fn from_base_ptr(
        base_ptr: *mut u8,
        max_bytes: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut shmem_idx: usize = 0;

        // Get the stat header
        let mut max_data_len: *mut u16 = null_mut();
        let mut static_len: u16 = 0;
        let header: &StatHeader = match stat_static_data_len(unsafe { *(base_ptr as *mut _) }) {
            Some(l) => {
                static_len = l;
                shmem_idx += size_of::<StatHeader>();
                unsafe { &*(base_ptr as *const _) }
            }
            None => {
                let dyn_header: &mut StatHeaderDyn = unsafe { &mut *(base_ptr as *mut _) };
                max_data_len = &mut dyn_header.data_len;
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

        let data_ptr = unsafe { base_ptr.add(shmem_idx) as *mut _ };
        // Enough bytes left for the data
        if !max_data_len.is_null() {
            shmem_idx += (unsafe { *max_data_len }) as usize;
        } else {
            shmem_idx += static_len as usize;
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
            str_repr: String::new(),
        })
    }
    /// The total space used in the stats file for this stat
    pub fn mem_len(&self) -> usize {
        let max_data_len = match stat_static_data_len(self.t) {
            Some(l) => l as usize,
            None => {
                // Dynamic size field + data size
                size_of::<u16>() + (unsafe { *self.max_data_len }) as usize
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
    /// Returns a reference to the stat data
    pub fn get_data(&self) -> StatVal {
        unsafe {
            match self.t {
                STAT_NEWCOMPONENT => StatVal::Component(std::str::from_utf8_unchecked(
                    std::slice::from_raw_parts(self.tag_ptr, self.tag_len as usize),
                )),
                STAT_BYTES => {
                    let buf_start = self.data_ptr.add(size_of::<u16>());
                    StatVal::Bytes(std::slice::from_raw_parts(
                        buf_start,
                        (*(self.data_ptr as *mut u16)) as usize,
                    ))
                }
                STAT_STR => {
                    let buf_start = self.data_ptr.add(size_of::<u16>());
                    StatVal::Str(std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                        buf_start,
                        (*(self.data_ptr as *mut u16)) as usize,
                    )))
                }
                STAT_USIZE => StatVal::USize(&*(self.data_ptr as *mut usize)),
                STAT_ISIZE => StatVal::ISize(&*(self.data_ptr as *mut isize)),
                STAT_U8 => StatVal::U8(&*(self.data_ptr as *mut u8)),
                STAT_U16 => StatVal::U16(&*(self.data_ptr as *mut u16)),
                STAT_U32 => StatVal::U32(&*(self.data_ptr as *mut u32)),
                STAT_U64 => StatVal::U64(&*(self.data_ptr as *mut u64)),
                STAT_I8 => StatVal::I8(&*(self.data_ptr as *mut i8)),
                STAT_I16 => StatVal::I16(&*(self.data_ptr as *mut i16)),
                STAT_I32 => StatVal::I32(&*(self.data_ptr as *mut i32)),
                STAT_I64 => StatVal::I64(&*(self.data_ptr as *mut i64)),
                _ => panic!("Invalid StatType given..."),
            }
        }
    }

    /// Returns the current length of the data
    pub fn len(&self) -> usize {
        match self.t {
            STAT_NEWCOMPONENT => 0,
            STAT_BYTES | STAT_STR => (unsafe { *(self.data_ptr as *mut u16) }) as usize,
            STAT_USIZE => size_of::<usize>(),
            STAT_ISIZE => size_of::<isize>(),
            STAT_U8 => size_of::<u8>(),
            STAT_U16 => size_of::<u16>(),
            STAT_U32 => size_of::<u32>(),
            STAT_U64 => size_of::<u64>(),
            STAT_I8 => size_of::<i8>(),
            STAT_I16 => size_of::<i16>(),
            STAT_I32 => size_of::<i32>(),
            STAT_I64 => size_of::<i64>(),
            _ => panic!("Invalid StatType given..."),
        }
    }

    /// Converts the current value to a string and cache it
    pub fn update_str_repr(&mut self) -> &str {
        use std::fmt::Write;
        self.str_repr.clear();
        match self.get_data() {
            StatVal::Component(v) | StatVal::Str(v) => {
                self.str_repr.push_str(v);
            }
            StatVal::Bytes(v) => {
                let _ = write!(self.str_repr, "{:?}", v);
            }
            StatVal::USize(v) => {
                let _ = write!(self.str_repr, "{}", v);
            }
            StatVal::ISize(v) => {
                let _ = write!(self.str_repr, "{}", v);
            }
            StatVal::U8(v) => {
                let _ = write!(self.str_repr, "{}", v);
            }
            StatVal::U16(v) => {
                let _ = write!(self.str_repr, "{}", v);
            }
            StatVal::U32(v) => {
                let _ = write!(self.str_repr, "{}", v);
            }
            StatVal::U64(v) => {
                let _ = write!(self.str_repr, "{}", v);
            }
            StatVal::I8(v) => {
                let _ = write!(self.str_repr, "{}", v);
            }
            StatVal::I16(v) => {
                let _ = write!(self.str_repr, "{}", v);
            }
            StatVal::I32(v) => {
                let _ = write!(self.str_repr, "{}", v);
            }
            StatVal::I64(v) => {
                let _ = write!(self.str_repr, "{}", v);
            }
        };
        &self.str_repr
    }

    /// Builds pretty string based on tag postfix
    pub fn update_pretty_str_repr(&mut self) -> &str {
        use std::fmt::Write;
        self.str_repr.clear();
        match self.get_data() {
            StatVal::Component(v) | StatVal::Str(v) => {
                self.str_repr.push_str(v);
            }
            StatVal::Bytes(v) => {
                let _ = write!(self.str_repr, "{:?}", v);
            }
            StatVal::USize(v) => {
                let _ = write!(self.str_repr, "{}", v);
            }
            StatVal::ISize(v) => {
                let _ = write!(self.str_repr, "{}", v);
            }
            StatVal::U8(v) => {
                let _ = write!(self.str_repr, "{}", v);
            }
            StatVal::U16(v) => {
                let _ = write!(self.str_repr, "{}", v);
            }
            StatVal::U32(v) => {
                let _ = write!(self.str_repr, "{}", v);
            }
            StatVal::U64(v) => {
                let _ = write!(self.str_repr, "{}", v);
                if self.get_tag().ends_with("_time") {
                    let mut formatted = String::new();
                    let cur_len = self.str_repr.len();
                    if cur_len > 6 {
                        formatted.push_str(&self.str_repr[..cur_len - 6]);
                        formatted.push('.');
                        formatted.push_str(&self.str_repr[cur_len - 6..cur_len - 3]);
                        formatted.push_str(" s");
                        self.str_repr = formatted;
                    } else if cur_len > 3 {
                        formatted.push_str(&self.str_repr[..cur_len - 3]);
                        formatted.push('.');
                        formatted.push_str(&self.str_repr[cur_len - 3..]);
                        formatted.push_str(" ms");
                        self.str_repr = formatted;
                    } else {
                        self.str_repr.push_str(" us");
                    }
                }
            }
            StatVal::I8(v) => {
                let _ = write!(self.str_repr, "{}", v);
            }
            StatVal::I16(v) => {
                let _ = write!(self.str_repr, "{}", v);
            }
            StatVal::I32(v) => {
                let _ = write!(self.str_repr, "{}", v);
            }
            StatVal::I64(v) => {
                let _ = write!(self.str_repr, "{}", v);
            }
        };
        &self.str_repr
    }

    pub fn as_str(&self) -> &str {
        &self.str_repr
    }
}

/// Helper to write dynamically sized stats to memory
pub fn update_dyn_stat<B: AsRef<[u8]>>(data_ptr: *mut u8, data: B) {
    // Set the current size to 0
    unsafe {
        *(data_ptr as *mut u16) = 0x0000;
    }

    // Copy over the data
    let src_buf = data.as_ref();
    let dst_buf: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(data_ptr.add(size_of::<u16>()), src_buf.len()) };
    dst_buf.copy_from_slice(&src_buf);

    // Set the new length
    unsafe {
        *(data_ptr as *mut u16) = src_buf.len() as u16;
    }
}

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
