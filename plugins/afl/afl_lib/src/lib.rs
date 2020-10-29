mod defines;
pub use defines::*;

/// (*mut AflState) Contains the state that most afl plugins need to function
pub const STORE_AFL_GLOBALS: &str = "afl_globals";
/// (*mut Vec<AflQueueEntry>) Holds AFL specific information about the current inputs
pub const STORE_AFL_QUEUE: &str = "afl_queue";


pub struct AflQueueEntry {
    pub cal_failed: bool,
    pub time_done: bool,
    pub was_fuzzed: bool,
    pub passed_det: bool,
    pub has_new_cov: bool,
    pub var_behavior: bool,
    pub favored: bool,
    pub fs_redundant: bool,

    pub bitmap_size: u32,
    pub exec_cksum: u32,

    pub exec_us: u64,
    pub handicap: u64,
    pub depth: u64,
}

impl Default for AflQueueEntry {
    fn default() -> Self {
        Self {
            cal_failed: false,
            time_done: false,
            was_fuzzed: false,
            passed_det: false,
            has_new_cov: false,
            var_behavior: false,
            favored: false,
            fs_redundant: false,
            bitmap_size: 0,
            exec_cksum: 0,
            exec_us: 0,
            handicap: 0,
            depth: 0,
        }
    }
}

pub type AflQueue = Vec<AflQueueEntry>;

pub struct AflGlobals {
    pub skip_deterministic: bool,
    pub total_cal_us: u64,
    pub total_cal_cycles: u64,
    pub total_bitmap_size: u64,
    pub total_bitmap_entries: u64,
}
impl Default for AflGlobals {
    fn default() -> Self {
        Self {
            skip_deterministic: false,
            total_cal_us: 0,
            total_cal_cycles: 0,
            total_bitmap_size: 0,
            total_bitmap_entries: 0,
        }
    }
}
