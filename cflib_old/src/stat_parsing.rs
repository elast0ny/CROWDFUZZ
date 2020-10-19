use std::mem::size_of;
use std::ptr::copy_nonoverlapping;

use log::*;
use nom::{bytes::complete::take, number::complete::*, IResult};

use crate::*;

/// Holds valid pointers into a stat field in shared memory
#[derive(Debug)]
pub struct StatRef {
    t: StatType,
    tag_len: u16,
    tag_ptr: *mut u8,
    max_data_len: u16,
    data_ptr: *mut u8,
}
impl StatRef {
    pub(self) fn empty() -> Self {
        use std::ptr::null_mut;
        Self {
            t: 0,
            tag_len: 0,
            tag_ptr: null_mut(),
            max_data_len: 0,
            data_ptr: null_mut(),
        }
    }
    /// Creates a StatRef instance from raw bytes
    pub(self) fn from_bytes(mut i: &[u8]) -> IResult<&[u8], Self> {
        //trace!("Parsing stat");
        let (_, stat_type) = le_u8(i)?;
        //trace!("\ttype : {}", stat_type);
        let header: &StatHeader;
        let mut max_data_len: u16;
        match stat_static_data_len(stat_type as _) {
            Some(static_len) => {
                max_data_len = static_len;
                let r = take(size_of::<StatHeader>() as u8)(i)?;
                i = r.0;
                header = unsafe { &*(r.1.as_ptr() as *const StatHeader) };
            }
            None => {
                let r = take(size_of::<StatHeaderDyn>() as u8)(i)?;
                i = r.0;
                let dyn_header = unsafe { &*(r.1.as_ptr() as *const StatHeaderDyn) };
                max_data_len = dyn_header.data_len;
                header = &dyn_header.header;
            }
        };
        //trace!("\tTagSz : {}", header.tag_len);
        //trace!("\tMaxSz : {}", max_data_len);

        let (t, bytes) = take(header.tag_len as u8)(i)?;
        i = t;
        let tag_ptr = bytes.as_ptr();

        // The "data" for new_component stats are their tags
        let data_ptr = if header.stat_type as u32 == STAT_NEWCOMPONENT {
            max_data_len = header.tag_len;
            tag_ptr
        } else {
            let (t, bytes) = take(max_data_len as u32)(i)?;
            i = t;
            bytes.as_ptr()
        };

        Ok((
            i,
            Self {
                t: stat_type as _,
                tag_len: header.tag_len,
                tag_ptr: tag_ptr as *mut _,
                max_data_len,
                data_ptr: data_ptr as *mut _,
            },
        ))
    }
    /// Returns a reference to the stat tag
    pub fn get_tag(&self) -> &str {
        //println!("{:p}[{}] = ", self.tag_ptr, self.tag_len);
        unsafe {
            std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                self.tag_ptr,
                self.tag_len as usize,
            ))
        }
    }
    /// Returns the type of the stat
    pub fn get_type(&self) -> StatType {
        self.t
    }
    /// Returns a copy of the value. The potential allocation will always
    /// be big enough to hold the biggest value of the current stat
    pub fn to_owned(&self) -> StatCopy {
        unsafe {
            match self.t as _ {
                STAT_NEWCOMPONENT => {
                    let mut res = Vec::with_capacity(self.tag_len as usize);
                    copy_nonoverlapping(self.tag_ptr, res.as_mut_ptr(), self.tag_len as usize);
                    res.set_len(self.tag_len as usize);
                    StatCopy::Component(String::from_utf8_unchecked(res))
                }
                STAT_BYTES => {
                    let mut res = Vec::with_capacity(self.max_data_len as usize);
                    let cur_len = copy_dyn_stat(res.as_mut_ptr(), self.data_ptr);
                    res.set_len(cur_len);
                    StatCopy::Bytes(res)
                }
                STAT_STR => {
                    let mut res = Vec::with_capacity(self.max_data_len as usize);
                    let cur_len = copy_dyn_stat(res.as_mut_ptr(), self.data_ptr);
                    res.set_len(cur_len);
                    StatCopy::Str(String::from_utf8_unchecked(res))
                }
                STAT_NUMBER => StatCopy::Number(*(self.data_ptr as *mut u64)),
                t => panic!("Invalid StatType given '{}' ...", t),
            }
        }
    }
    /// Returns whether this is a new component stat
    pub fn is_component(&self) -> bool {
        self.t == STAT_NEWCOMPONENT as _
    }
}

//Owned stat value
pub enum StatCopy {
    Component(String),
    Bytes(Vec<u8>),
    Str(String),
    Number(u64),
}
impl StatCopy {
    /// Whether the copy is equal to the real value
    pub fn is_equal(&self, src: &StatRef) -> bool {
        unsafe {
            match self {
                StatCopy::Component(_) => true,
                StatCopy::Bytes(dst) => {
                    if *(src.data_ptr as *mut u16) as usize != dst.len() {
                        false
                    } else {
                        let bytes = std::slice::from_raw_parts(
                            src.data_ptr.add(size_of::<u16>()),
                            dst.len(),
                        );
                        dst == &bytes
                    }
                }
                StatCopy::Str(dst) => {
                    if *(src.data_ptr as *mut u16) as usize != dst.len() {
                        false
                    } else {
                        let bytes = std::slice::from_raw_parts(
                            src.data_ptr.add(size_of::<u16>()),
                            dst.len(),
                        );
                        dst.as_bytes() == bytes
                    }
                }
                StatCopy::Number(v) => *v == *(src.data_ptr as *mut u64),
            }
        }
    }
    /// Updates itself to match the current value
    pub fn update(&mut self, src: &StatRef) {
        unsafe {
            match self {
                StatCopy::Component(_) => {}
                StatCopy::Bytes(dst) => {
                    let cur_len = copy_dyn_stat(dst.as_mut_ptr(), src.data_ptr);
                    dst.set_len(cur_len);
                }
                StatCopy::Str(dst) => {
                    let dst = dst.as_mut_vec();
                    let cur_len = copy_dyn_stat(dst.as_mut_ptr(), src.data_ptr);
                    dst.set_len(cur_len);
                }
                StatCopy::Number(v) => *v = *(src.data_ptr as *mut u64),
            }
        }
    }
    /// Write its contents to a string representation
    pub fn write_str(&self, dst: &mut String) {
        use std::fmt::Write;
        dst.clear();
        let _ = match self {
            StatCopy::Component(v) => write!(dst, "{}", v),
            StatCopy::Bytes(v) => {
                for byte in v {
                    let _ = write!(dst, "{:02X}", byte);
                }
                Ok(())
            }
            StatCopy::Str(v) => write!(dst, "{}", v),
            StatCopy::Number(v) => write!(dst, "{}", v),
        };
    }
    /// Returns a reference to its contents if of type `Str`
    pub fn as_str(&self) -> Option<&str> {
        match self {
            StatCopy::Component(v) | StatCopy::Str(v) => Some(v.as_str()),
            _ => None,
        }
    }
    /// Returns a reference to its contents if of type `Bytes`
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            StatCopy::Bytes(v) => Some(&v),
            _ => None,
        }
    }
    /// Returns its contents if of type `Number`
    pub fn as_num(&self) -> Option<u64> {
        match self {
            StatCopy::Number(v) => Some(*v),
            _ => None,
        }
    }
    /// Returns its contents as signed if of type `Number`
    pub fn as_signed_num(&self) -> Option<i64> {
        match self {
            StatCopy::Number(v) => Some(*v as i64),
            _ => None,
        }
    }
}
use std::fmt;
impl fmt::Display for StatCopy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut res = String::new();
        self.write_str(&mut res);
        write!(f, "{}", res.as_str())
    }
}

#[derive(Debug)]
/// Component statistics
pub struct Component {
    pub name: StatRef,
    pub stats: Vec<StatRef>,
}
/// Fuzzer statistics
#[derive(Debug)]
pub struct FuzzerStats {
    pub pid: u32,
    /// Holds the core's stats
    pub inner: Component,
    /// List of plugins with their stats
    pub plugins: Vec<Component>,
}
impl FuzzerStats {
    /// Parses the stat memory after the stat header
    fn populate_stats<'a>(&mut self, mut i: &'a [u8]) -> IResult<&'a [u8], ()> {
        // Get the core component
        let (t, stat) = StatRef::from_bytes(i)?;
        trace!("{:?}", stat);
        i = t;
        if !stat.is_component() {
            error!("First stat was not a NewComponent() stat !");
            return Err(nom::Err::Failure((i, nom::error::ErrorKind::IsNot)));
        }
        self.inner.name = stat;

        let mut cur_component = &mut self.inner;
        while !i.is_empty() {
            //Parse the next stat
            let (t, stat) = StatRef::from_bytes(i)?;
            trace!("{:?}", stat);
            i = t;
            // New component
            if stat.is_component() {
                self.plugins.push(Component {
                    name: stat,
                    stats: Vec::new(),
                });
                cur_component = self.plugins.last_mut().unwrap();
                continue;
            }

            // Add stat to current component
            cur_component.stats.push(stat);
        }

        Ok((i, ()))
    }

    ///Returns the stat header if the fuzzer is currently running and initialized
    unsafe fn get_header(src: *mut u8) -> Result<&'static StatFileHeader, &'static str> {
        let header: &StatFileHeader = &*(src as *const _);
        if header.stat_len == 0 || header.state != CORE_FUZZING {
            Err("header is invalid")
        } else {
            Ok(header)
        }
    }

    /// Parses a fuzzer's statistics memory
    /// # Safety
    /// This function is unsafe as it dereferences an arbitrary pointer
    pub unsafe fn from_ptr(src: *mut u8) -> Result<Self, &'static str> {
        // Get the header
        let header: &StatFileHeader = Self::get_header(src)?;

        let stat_buf: &[u8] = std::slice::from_raw_parts(
            src.add(size_of::<StatFileHeader>()),
            (header.stat_len as usize) - size_of::<StatFileHeader>(),
        );

        if stat_buf.is_empty() {
            return Err("No stat data available");
        }

        let mut fuzzer = Self {
            pid: header.pid,
            inner: Component {
                name: StatRef::empty(),
                stats: Vec::new(),
            },
            plugins: Vec::new(),
        };

        if fuzzer.populate_stats(stat_buf).is_err() {
            return Err("stat memory is corrupted");
        }

        Ok(fuzzer)
    }
}

// =============================
// Pretty formatting stuff below
// =============================

/// Returns the static length of a specific stat type if available
fn stat_static_data_len(some_val: StatType) -> Option<u16> {
    match some_val as _ {
        STAT_NEWCOMPONENT => Some(0),
        STAT_BYTES => None,
        STAT_STR => None,
        STAT_NUMBER => Some(size_of::<u64>() as u16),
        t => panic!("Invalid StatType given : {}...", t),
    }
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

    for val in TAG_PREFIX {
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
            if *postfix == STR_POSTFIX_DIR_STR {
                return (tag, Some(*postfix));
            } else {
                return (&tag[..tag_len - postfix_len], Some(*postfix));
            }
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

    (tag, None)
}

const US_IN_MS: u64 = 1000;
const US_IN_S: u64 = 1000 * US_IN_MS;
const US_IN_M: u64 = 60 * US_IN_S;
const US_IN_H: u64 = 60 * US_IN_M;

// Caller must clear the string before calling
fn format_duration(dst: &mut String, mut val: u64, unit: &str) {
    use std::fmt::Write;
    let mut got_long_scale = false;
    // conver to us
    val *= match unit {
        "ms" => US_IN_MS,
        "s" => US_IN_S,
        "m" => US_IN_M,
        "h" => US_IN_H,
        _ => 1,
    };

    if val > US_IN_H {
        let _ = write!(dst, "{}h", val / US_IN_H);
        val %= US_IN_H;
        got_long_scale = true;
    }
    if val > US_IN_M {
        let _ = write!(dst, "{}m", val / US_IN_M);
        val %= US_IN_M;
        got_long_scale = true;
    }
    if val > US_IN_S {
        let _ = write!(dst, "{}", val / US_IN_S);
        val %= US_IN_S;
        if val > US_IN_MS {
            let _ = write!(dst, ".{}s", val / US_IN_MS);
        } else {
            let _ = write!(dst, "s");
        }
        got_long_scale = true;
    }

    // Write smaller time scales
    if !got_long_scale {
        if val > US_IN_MS {
            let _ = write!(dst, "{}ms", val / US_IN_MS);
        } else if val > 0 {
            let _ = write!(dst, "{}us", val);
        } else {
            let _ = write!(dst, "[None]");
        }
    }
}

/// Writes the stat as its pretty string version using tag type hints
pub fn write_pretty_stat(dst: &mut String, src: &StatCopy, tag_postfix: &str) {
    use std::fmt::Write;

    let num = src.as_num();

    if let Some(num) = num {
        let unit = match tag_postfix.rfind('_') {
            Some(idx) => &tag_postfix[idx + 1..],
            None => "us",
        };

        dst.clear();
        format_duration(dst, num, unit);
    } else if let Some(mut s) = src.as_str() {
        dst.clear();
        if tag_postfix == STR_POSTFIX_DIR_STR {
            // Strip windows path grossness
            if s.starts_with("\\\\?\\") {
                s = &s[4..];
            }
        }
        let _ = write!(dst, "{}", s);
    } else if let Some(b) = src.as_bytes() {
        dst.clear();
        if tag_postfix == BYTES_POSTFIX_HEX_STR {
            for byte in b {
                let _ = write!(dst, "{:X}", byte);
            }
        } else {
            let _ = write!(dst, "{:?}", b);
        }
    }
}
