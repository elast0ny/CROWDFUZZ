use simple_parse::*;
use std::sync::atomic::AtomicU8;

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


/// The states that the fuzzer core can have
#[derive(SpRead, Debug, Clone, Copy)]
#[sp(id_type = "u8")]
pub enum CoreState {
    /// The core is in this state during load() and pre_fuzz()
    /// Stats should not be used when in this state
    #[sp(id = "0")]
    Initializing,
    /// During fuzz(). Stats memory is safe to read.
    #[sp(id = "1")]
    Fuzzing,
    #[sp(id = "2")]
    Exiting,
}

pub const STAT_MAGIC: u32 = 0xBADC0FFE;

/// Describes the statistic layout of a CROWDFUZZ instance
/// Use simple_parse::SpRead to instanciate : CfStats::from_bytes(...)
#[derive(SpRead, Debug)]
pub struct CfStats {
    pub magic: u32,
    pub state: CoreState,
    pub pid: u32,
    num_plugins: u16,
    #[sp(count = "num_plugins")]
    pub plugins: Vec<PluginStats>,
}

/// Describes a plugin and its stats
#[derive(SpRead, Debug)]
pub struct PluginStats {
    pub name: String,
    num_stats: u32,
    #[sp(count = "num_stats")]
    pub stats: Vec<Stat>,
}

/// Holds a stat tag and its value
#[derive(SpRead, Debug)]
pub struct Stat {
    pub tag: String,
    pub val: StatVal,
}

/// Different types of statistics
#[derive(SpRead, Debug)]
#[sp(id_type = "u8")]
pub enum StatVal {
    #[sp(id = "0")]
    Num(StatNum),
    #[sp(id = "1")]
    Bytes(StatBytes),
    #[sp(id = "2")]
    Str(StatStr),
}

/// Holds a reference to a number living in shared memory
/// This reference is valid for the lifetime of the plugin
pub struct StatNum {
    pub val: &'static mut u64,
}
impl StatNum {
    pub fn set(&mut self, new_val: u64) {
        *self.val = new_val
    }
    pub fn get(&self) -> &u64 {
        self.val
    }
}

/// Holds a reference to a string living in shared memory
/// The get/set function use a spinlock to safely manage access to this data
/// This reference is valid for the lifetime of the plugin
pub struct StatStr {
    pub(crate) lock: &'static mut AtomicU8,
    pub(crate) val: GenericBuf,
}
impl StatStr {
    pub fn set(&mut self, new_val: &str) {
        acquire(self.lock);
        self.val.set(new_val.as_bytes());
        release(self.lock);
    }
    pub fn get<'a>(&'a mut self) -> LockGuard<&'a str> {
        acquire(self.lock);

        // Convert current buf to a utf8 str
        let s = match std::str::from_utf8(self.val.get()) {
            Ok(s) => s,
            Err(_) => "<INVALID UTF8>",
        };

        LockGuard::new(self.lock, s)
    }
}

/// Holds a reference to bytes living in shared memory
/// The get/set function use a spinlock to safely manage access to this data
/// This reference is valid for the lifetime of the plugin
pub struct StatBytes {
    pub(crate) lock: &'static mut AtomicU8,
    pub(crate) val: GenericBuf,
}
impl StatBytes {
    pub fn set(&mut self, new_val: &[u8]) {
        acquire(self.lock);
        self.val.set(new_val);
        release(self.lock);
    }
    pub fn get<'a>(&'a mut self) -> LockGuard<&'a [u8]> {
        acquire(self.lock);
        LockGuard::new(self.lock, self.val.get())
    }
}

/// Attemps to get a PID from the shared memory. If the fuzzer
/// hasn't initialized the shared memory after 1s, Ok(None) is returned.
pub unsafe fn get_fuzzer_pid(shmem_start: *mut u8) -> Result<Option<u32>> {
    let magic_ptr = shmem_start as *mut u32;
    if *magic_ptr != STAT_MAGIC {
        return Err(From::from("Fuzzer stats invalid".to_string()));
    }

    let mut num_checks = 0;
    let state_ptr = magic_ptr.add(1) as *mut CoreState;

    // Wait until shmem is initialized
    while let CoreState::Initializing = *state_ptr {
        std::thread::sleep(std::time::Duration::from_millis(200));
        num_checks += 1;
        if num_checks == 5 {
            // Fuzzer didnt init in time
            return Ok(None);
        }
    }

    let pid_ptr = state_ptr.add(1) as *mut u32;
    Ok(Some(*pid_ptr))
}
