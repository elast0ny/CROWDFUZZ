use simple_parse::{SpReadRawMut, SpReadRaw};
use std::sync::atomic::AtomicU8;
use std::ptr::copy_nonoverlapping;

use crate::*;

/// UIs can add up these values
pub const TAG_PREFIX_TOTAL: &str = "total_";
/// UIs can combine these values into an average
pub const TAG_PREFIX_AVG: &str = "avg_";
pub(crate) const TAG_PREFIXES: &[&str] = &[TAG_PREFIX_TOTAL, TAG_PREFIX_AVG];

/// Display numbers/bytes as hex
pub const TAG_POSTFIX_HEX: &str = "_hex";
/// Cleanup file path strings
pub const TAG_POSTFIX_PATH: &str = "_dir";
/// Show time since this timestamp
pub const TAG_POSTFIX_EPOCHS: &str = "_epoch_s";
/// Nanoseconds
pub const TAG_POSTFIX_NS: &str = "_ns";
/// Microseconds
pub const TAG_POSTFIX_US: &str = "_us";
/// Milliseconds
pub const TAG_POSTFIX_MS: &str = "_ms";
/// Seconds
pub const TAG_POSTFIX_SEC: &str = "_s";
/// Minutes
pub const TAG_POSTFIX_MIN: &str = "_m";
/// Hours
pub const TAG_POSTFIX_HOUR: &str = "_h";
/// Holds an intersting result
pub const TAG_POSTFIX_RESULT: &str = "_res";

pub(crate) const TAG_POSTFIXES: &[&str] = &[
    TAG_POSTFIX_HEX,
    TAG_POSTFIX_PATH,
    TAG_POSTFIX_EPOCHS,
    TAG_POSTFIX_NS,
    TAG_POSTFIX_US,
    TAG_POSTFIX_MS,
    TAG_POSTFIX_SEC,
    TAG_POSTFIX_MIN,
    TAG_POSTFIX_HOUR,
    TAG_POSTFIX_RESULT,
];

/**
 * Stat tags bellow should be used when possible for consistency
 * on important/common stats
 */

/// Average target exec time
pub const STAT_TARGET_EXEC_TIME: &str = "avg_target_exec_time_ns";
/// Number crashes
pub const STAT_NUM_CRASHES: &str = "total_crashes_res";
/// Number of timeouts
pub const STAT_NUM_TIMEOUTS: &str = "total_timeouts_res";

pub const STAT_MAGIC: u32 = 0xBADC0FFE;
#[derive(SpReadRawMut, SpReadRaw, Debug)]
pub struct CfStatsHeader<'b> {
    pub magic: &'b u32,
    pub initialized: &'b u8,
    pub pid: &'b u32,
}

/// Describes the statistic layout of a CROWDFUZZ instance
/// Use simple_parse::SpRead to instanciate : CfStats::from_bytes(...)
#[derive(SpReadRawMut, Debug)]
pub struct CfStats<'b> {
    pub header: CfStatsHeader<'b>,
    pub plugins: Vec<PluginStats<'b>>,
}

/// Describes a plugin and its stats
#[derive(SpReadRawMut, Debug)]
pub struct PluginStats<'b> {
    pub name: &'b str,
    num_stats: &'b u32,
    #[sp(count = "num_stats")]
    pub stats: Vec<Stat<'b>>,
}

/// Holds a stat tag and its value
#[derive(SpReadRawMut, Debug)]
pub struct Stat<'b> {
    pub tag: String,
    pub val: StatVal<'b>,
}

/// Different types of statistics
#[derive(SpReadRawMut, Debug)]
#[sp(id_type = "u8")]
pub enum StatVal<'b> {
    #[sp(id = "0")]
    Num(StatNum<'b>),
    #[sp(id = "1")]
    Bytes(StatBytes<'b>),
    #[sp(id = "2")]
    Str(StatStr<'b>),
}

/// Holds a reference to a number living in shared memory
/// This reference is valid for the lifetime of the plugin
#[derive(SpReadRawMut)]
pub struct StatNum<'b> {
    pub val: &'b mut u64,
}

/// Holds a reference to a string living in shared memory
/// The get/set function use a spinlock to safely manage access to this data
/// This reference is valid for the lifetime of the plugin
#[derive(SpReadRawMut)]
pub struct StatStr<'b> {
    pub(crate) lock: &'b mut AtomicU8,
    pub(crate) capacity: &'b u32,
    pub(crate) len: &'b mut u32,
    #[sp(count = "capacity")]
    pub(crate) buf: &'b mut [u8],
}
impl<'b> StatStr<'b> {
    pub fn set<S: AsRef<str>>(&mut self, new_val: S) {
        acquire(self.lock);
        let src = new_val.as_ref().as_bytes();
        let new_len = std::cmp::min(*self.capacity as usize, src.len());
        unsafe {
            copy_nonoverlapping(src.as_ptr(), self.buf.as_mut_ptr(), new_len);
        }
        *self.len = new_len as u32;

        release(self.lock);
    }
    pub fn get<'a>(&'a mut self) -> LockGuard<&'a str> {
        acquire(self.lock);

        // Convert current buf to a utf8 str
        let s = match std::str::from_utf8(&self.buf[..*self.len as usize]) {
            Ok(s) => s,
            Err(_) => "<INVALID UTF8>",
        };

        LockGuard::new(self.lock, s)
    }
}

/// Holds a reference to bytes living in shared memory
/// The get/set function use a spinlock to safely manage access to this data
/// This reference is valid for the lifetime of the plugin
#[derive(SpReadRawMut)]
pub struct StatBytes<'b> {
    pub(crate) lock: &'b mut AtomicU8,
    pub(crate) capacity: &'b u32,
    pub(crate) len: &'b mut u32,
    #[sp(count = "capacity")]
    pub(crate) buf: &'b mut [u8],
}
impl<'b> StatBytes<'b> {
    pub fn set<B: AsRef<[u8]>>(&mut self, new_val: B) {
        acquire(self.lock);
        
        let src = new_val.as_ref();
        let new_len = std::cmp::min(*self.capacity as usize, src.len());

        unsafe {
            copy_nonoverlapping(src.as_ptr(), self.buf.as_mut_ptr(), new_len);
        }
        
        *self.len = new_len as u32;

        release(self.lock);
    }
    pub fn get<'a>(&'a mut self) -> LockGuard<&'a [u8]> {
        acquire(self.lock);
        LockGuard::new(self.lock, &self.buf[..*self.len as usize])
    }
}

/// Attemps to get a PID from the shared memory. If the fuzzer
/// hasn't initialized the shared memory after 1s, Ok(None) is returned.
pub fn get_fuzzer_pid(shmem_buf: &[u8]) -> Result<Option<u32>> {
    let mut cur = std::io::Cursor::new(shmem_buf);
    let header = CfStatsHeader::from_slice(&mut cur)?;

    if *header.magic != STAT_MAGIC {
        return Err(From::from("Fuzzer stats invalid".to_string()));
    }

    let mut num_checks = 0;
    // Wait until shmem is initialized
    while *header.initialized == 0 {
        std::thread::sleep(std::time::Duration::from_millis(200));
        num_checks += 1;
        if num_checks == 5 {
            // Fuzzer didnt init in time
            return Ok(None);
        }
    }

    Ok(Some(*header.pid))
}
