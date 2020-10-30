use crate::*;

use ::rand::rngs::SmallRng;
use ::rand::{Rng, SeedableRng};

#[derive(Debug)]
pub struct HavocState {
    num_iterations: usize,
    /// fast/non-crypto grade random
    rng: SmallRng,
}
impl HavocState {
    pub fn new(q: &mut AflQueueEntry, afl: &AflGlobals) -> Self {
        // Calculate perf_score from entry.exec_us and bitmap_size
        let mut r = Self {
            num_iterations: 0,
            rng: SmallRng::from_rng(&mut ::rand::thread_rng()).unwrap(),
        };
        r.reset(q, afl);
        r
    }

    pub fn desc(&self, dst: &mut String) {
        dst.push_str("havoc");
    }

    pub fn iterations(&self) -> usize {
        self.num_iterations
    }

    pub fn reset(&mut self, q: &mut AflQueueEntry, afl: &AflGlobals) {
        // Update weight for cur input
        let perf_score = calculate_score(q, afl);

        // Recalculate number of iterations based on weight
        self.num_iterations = if afl.skip_deterministic {
            HAVOC_CYCLES
        } else {
            HAVOC_CYCLES_INIT
        } as usize * (perf_score as usize) / 1 / 100;
    }

    pub fn mutate(&mut self, input: &mut CfInput) -> StageResult {
        let bytes = unsafe { input.chunks.get_unchecked_mut(0) };
        self.num_iterations -= 1;

        if self.num_iterations == 0 {
            return StageResult::Done;
        }

        bytes[0] = 0x00;

        StageResult::CantRestoreInput
    }
}

pub fn calculate_score(q: &mut AflQueueEntry, afl: &AflGlobals) -> u32 {
    let avg_exec_us = (afl.total_cal_us / afl.total_cal_cycles) as usize;
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

    if afl.total_bitmap_entries != 0 {
        let avg_bitmap_size = (afl.total_bitmap_size / afl.total_bitmap_entries) as usize;
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

    //println!("Score {}", perf_score);
    perf_score
}
