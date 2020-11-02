use std::ptr::{copy, copy_nonoverlapping};

use ::rand::rngs::SmallRng;
use ::rand::{Rng, SeedableRng};

use crate::*;

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

    pub fn total_cycles(&self) -> usize {
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
        } as usize
            * (perf_score as usize)
            / afl.havoc_div as usize
            / 100;

        if self.num_iterations < HAVOC_MIN {
            self.num_iterations = HAVOC_MIN;
        }
    }

    pub fn mutate(&mut self, input: &mut CfInput) -> StageResult {
        self.num_iterations -= 1;
        if self.num_iterations == 0 {
            return StageResult::Done;
        }

        let mut num_stacks = 1 << self.rng.gen_range(1, HAVOC_STACK_POW2);
        loop {
            unsafe {
                match self.rng.gen_range(0, 15) {
                    // Flip a single bit somewhere
                    0 => {
                        input.flip_bit(self.rng.gen_range(0, input.len() << 3));
                    }
                    // Set byte to interesting value
                    1 => {
                        input.set_byte(
                            self.rng.gen_range(0, input.len()),
                            *INTERESTING_8
                                .get_unchecked(self.rng.gen_range(0, INTERESTING_8.len())),
                        );
                    }
                    // Set word to interesting value
                    2 => {
                        if input.len() < 2 {
                            continue;
                        }
                        input.set_word(
                            self.rng.gen_range(0, input.len() - 1),
                            *INTERESTING_16
                                .get_unchecked(self.rng.gen_range(0, INTERESTING_16.len())),
                        );
                    }
                    // Set dword to intersting value
                    3 => {
                        if input.len() < 4 {
                            continue;
                        }
                        input.set_dword(
                            self.rng.gen_range(0, input.len() - 3),
                            *INTERESTING_32
                                .get_unchecked(self.rng.gen_range(0, INTERESTING_32.len())),
                        );
                    }
                    // Randomly subtract from byte.
                    4 => {
                        input.sub_byte(
                            self.rng.gen_range(0, input.len()),
                            self.rng.gen_range(1, (ARITH_MAX + 1) as u8),
                        );
                    }
                    // Randomly add to byte
                    5 => {
                        input.add_byte(
                            self.rng.gen_range(0, input.len()),
                            self.rng.gen_range(1, (ARITH_MAX + 1) as u8),
                        );
                    }
                    // Randomly subtract from word
                    6 => {
                        if input.len() < 2 {
                            continue;
                        }
                        input.sub_word(
                            self.rng.gen_range(0, input.len() - 1),
                            self.rng.gen_range(1, (ARITH_MAX + 1) as u16),
                        );
                    }
                    // Randomly add to word
                    7 => {
                        if input.len() < 2 {
                            continue;
                        }
                        input.add_word(
                            self.rng.gen_range(0, input.len() - 1),
                            self.rng.gen_range(1, (ARITH_MAX + 1) as u16),
                        );
                    }
                    // Randomly subtract from dword
                    8 => {
                        if input.len() < 4 {
                            continue;
                        }
                        input.sub_dword(
                            self.rng.gen_range(0, input.len() - 3),
                            self.rng.gen_range(1, (ARITH_MAX + 1) as u32),
                        );
                    }
                    // Randomly add to dword
                    9 => {
                        if input.len() < 4 {
                            continue;
                        }
                        input.add_dword(
                            self.rng.gen_range(0, input.len() - 3),
                            self.rng.gen_range(1, (ARITH_MAX + 1) as u32),
                        );
                    }
                    // Set a random byte to a random value
                    10 => {
                        let rand_idx = self.rng.gen_range(0, input.len());
                        let mut rand_val = self.rng.gen_range(0, 256) as u8;
                        // Make sure its different
                        while *input.get_unchecked(rand_idx) == rand_val {
                            rand_val = self.rng.gen_range(0, 256) as u8;
                        }
                        input.set_byte(rand_idx, rand_val);
                    }
                    // Delete bytes. We're making this a bit more likely than insertion (the next option) in hopes of keeping files reasonably small
                    11 | 12 => {
                        if input.len() < 2 {
                            continue;
                        }

                        let del_len = choose_block_len(input.len() - 1, &mut self.rng);
                        let del_from = self.rng.gen_range(0, input.len() - del_len + 1);

                        let out_buf = input.as_mut_ptr();
                        copy_nonoverlapping(out_buf.add(del_from + del_len), out_buf.add(del_from), input.len() - del_len - del_from);
                        input.set_len(input.len() - del_len);
                    }
                    // Insert a cloned chunk (75%) or a constant value (25%)
                    13 => {
                        // Dont insert if file is too big                        
                        if input.len() + HAVOC_BLK_XL as usize >= MAX_FILE as usize {
                            continue;
                        }
                        
                        let insert_idx = self.rng.gen_range(0, input.len());
                        let clone_len;
                        let mut clone_from = None;
                        
                        /* Clone bytes (75%) or insert a block of constant bytes (25%). */
                        if self.rng.gen_range(0, 4) != 0 {
                            clone_len = choose_block_len(input.len(), &mut self.rng);
                            clone_from = Some(self.rng.gen_range(0, input.len() - clone_len + 1));
                        } else {
                            clone_len = choose_block_len(HAVOC_BLK_XL as usize, &mut self.rng);
                        }
                        
                        input.reserve(clone_len);

                        // Shift the tail before overwriting some bytes
                        copy(input.as_ptr().add(insert_idx), input.as_mut_ptr().add(insert_idx + clone_len), input.len() - insert_idx);

                        if let Some(clone_start) = clone_from {
                            // Copy the cloned chunk
                            copy(input.as_ptr().add(clone_start), input.as_mut_ptr().add(insert_idx), clone_len);
                        } else {
                            // Copy a random value
                            let val = self.rng.gen_range(0, 256) as u8;
                            for i in insert_idx..insert_idx+clone_len {
                                *input.get_unchecked_mut(i) = val;
                            }
                        }

                        input.set_len(input.len() + clone_len);
                    }
                    // Overwrite bytes with a random chunk (75%) or a constant value (25%)
                    14 => {
                        if input.len() < 2 {
                            continue;
                        }

                        let copy_len = choose_block_len(input.len() - 1, &mut self.rng);
                        let copy_to = self.rng.gen_range(0, input.len() - copy_len + 1);

                        if self.rng.gen_range(0, 4) != 0 {
                            let copy_from = self.rng.gen_range(0, input.len() - copy_len + 1);
                            copy(input.as_ptr().add(copy_from), input.as_mut_ptr().add(copy_to), copy_len);
                        } else {
                            let val = self.rng.gen_range(0, 256) as u8;
                            for i in copy_to..copy_to+copy_len {
                                *input.get_unchecked_mut(i) = val;
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            }

            if num_stacks == 0 {
                break;
            }
            
            num_stacks -= 1;
        }

        // Reverting our changes will be too much
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

/* Helper to choose random block len for block operations in fuzz_one().
Doesn't return zero, provided that max_len is > 0. */

pub fn choose_block_len(limit: usize, rng: &mut SmallRng) -> usize {
    let mut min_value;
    let max_value;

    match rng.gen_range(0, 3) {
        0 => {
            min_value = 1;
            max_value = HAVOC_BLK_SMALL;
        }
        1 => {
            min_value = HAVOC_BLK_SMALL;
            max_value = HAVOC_BLK_MEDIUM;
        }
        _ => {
            if rng.gen_range(0, 10) != 0 {
                min_value = HAVOC_BLK_MEDIUM;
                max_value = HAVOC_BLK_LARGE;
            } else {
                min_value = HAVOC_BLK_LARGE;
                max_value = HAVOC_BLK_XL;
            }
        }
    }
    if min_value as usize >= limit {
        min_value = 1;
    }
    (min_value as usize) + rng.gen_range(0, std::cmp::min(max_value as usize, limit) - (min_value as usize) + 1)
}
