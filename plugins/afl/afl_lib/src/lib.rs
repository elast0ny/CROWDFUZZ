mod defines;
pub use defines::*;

/// (*mut AflState) Contains the state that most afl plugins need to function
pub const STORE_AFL_STATE: &str = "afl_state";
/// (*mut Vec<AflQueueEntry>) Holds AFL specific information about the current inputs
pub const STORE_AFL_QUEUE: &str = "afl_queue";

/// (*mut bool) Holds AFL specific information about the current inputs
pub const STORE_AFL_REUSE_INPUT: &str = "afl_queue";

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

pub struct AflState {
    pub skip_deterministic: bool,
    pub total_cal_us: u64,
    pub total_cal_cycles: u64,
    pub total_bitmap_size: u64,
    pub total_bitmap_entries: u64,
}
impl Default for AflState {
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

impl AflState {
    pub fn calculate_score(&mut self, q: &mut AflQueueEntry) -> u32 {
        let avg_exec_us = (self.total_cal_us / self.total_cal_cycles) as usize;
        let avg_bitmap_size = (self.total_bitmap_size / self.total_bitmap_entries) as usize;

        let mut perf_score = 100;
        /* Adjust score based on execution speed of this path, compared to the
        global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
        less expensive to fuzz, so we're giving them more air time. */

        if q.exec_us as f64 * 0.1 > avg_exec_us as _ {
            perf_score = 10;
        } else if q.exec_us as f64 * 0.25 > avg_exec_us as _ {
            perf_score = 25;
        } else if q.exec_us as f64 * 0.5 > avg_exec_us as _ {
            perf_score = 50;
        } else if q.exec_us as f64 * 0.75 > avg_exec_us as _ {
            perf_score = 75;
        } else if q.exec_us * 4 < avg_exec_us as _ {
            perf_score = 300;
        } else if q.exec_us * 3 < avg_exec_us as _ {
            perf_score = 200;
        } else if q.exec_us * 2 < avg_exec_us as _ {
            perf_score = 150;
        }
        /* Adjust score based on bitmap size. The working theory is that better
        coverage translates to better targets. Multiplier from 0.25x to 3x. */

        if q.bitmap_size as f32 * 0.3 > avg_bitmap_size as _ {
            perf_score *= 3;
        } else if q.bitmap_size as f32 * 0.5 > avg_bitmap_size as _ {
            perf_score *= 2;
        } else if q.bitmap_size as f32 * 0.75 > avg_bitmap_size as _ {
            perf_score = (1.5 * perf_score as f32) as _;
        } else if q.bitmap_size * 3 < avg_bitmap_size as _ {
            perf_score = (0.25 * perf_score as f32) as _;
        } else if q.bitmap_size * 2 < avg_bitmap_size as _ {
            perf_score = (0.5 * perf_score as f32) as _;
        } else if q.bitmap_size as f32 * 1.5 < avg_bitmap_size as _ {
            perf_score = (0.75 * perf_score as f32) as _;
        }
        /* Adjust score based on handicap. Handicap is proportional to how late
        in the game we learned about this path. Latecomers are allowed to run
        for a bit longer until they catch up with the rest. */
        if q.handicap >= 4 {
            perf_score *= 4;
            q.handicap -= 4;
        } else if q.handicap > 0 {
            perf_score *= 2;
            q.handicap -= 1;
        }

        // 0..3 == do nothing
        if q.depth >= 4 && q.depth <= 7 {
            perf_score *= 2
        } else if q.depth >= 8 && q.depth <= 13 {
            perf_score *= 3
        } else if q.depth >= 14 && q.depth <= 25 {
            perf_score *= 4;
        } else {
            perf_score *= 5;
        }
    
        if perf_score > HAVOC_MAX_MULT * 100 {
            perf_score = HAVOC_MAX_MULT * 100;
        }

        perf_score
    }
}
