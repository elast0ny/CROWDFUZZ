use crate::*;

use ::rand::rngs::SmallRng;
use ::rand::SeedableRng;

pub enum InnerStage<T> {
    Updated,
    Next(T),
    Done,
}

pub enum StageResult {
    /// Mutated input and will restore on next iteration
    WillRestoreInput,
    /// Mutated input and will not restore on next iteration
    CantRestoreInput,
    /// Didnt mutate, switching to next stage
    Next,
    /// Stage is done and has not mutated the input
    Done,
}

#[derive(Debug)]
pub enum Stages {
    /// Flips groups of bits [1,2,4,8,16,32]
    BitFlip(BitFlipState),
    /// Perform arithmetic operations [8,16,32]
    Arithmetic(ArithState),
    /// Insert interesting values [8,16,32]
    Interesting(InterestState),
    /*
    /// Use user provided values
    UserExtra,
    /// Automaticaly found values
    AutoExtra,
    */
    /// Do anything
    Havoc(HavocState),
}
pub struct InputMutateStage {
    pub cur_stage: Stages,
}
impl InputMutateStage {
    pub fn new(skip_deterministic: bool, input_len: usize) -> Self {
        // Go straight to havoc is skip_det
        let first_stage = if skip_deterministic {
            let s = HavocState::new(SmallRng::from_rng(&mut ::rand::thread_rng()).unwrap());
            Stages::Havoc(s)
        } else {
            let s = BitFlipState::new(input_len);
            Stages::BitFlip(s)
        };

        Self {
            cur_stage: first_stage,
        }
    }

    /// Mutates a given input based on the current stage.
    pub fn mutate(&mut self, input: &mut CfInput) -> StageResult {
        // Inputs always have only one chunk
        let bytes = unsafe { input.chunks.get_unchecked_mut(0) };

        match self.cur_stage {
            Stages::BitFlip(ref mut state) => {
                let r = bit_flip(bytes, state);
                if let StageResult::Done = r {
                    // Next stage with same input
                    self.cur_stage = Stages::Arithmetic(ArithState::new(bytes.len()));
                    StageResult::Next
                } else {
                    r
                }
            }
            Stages::Arithmetic(ref mut state) => {
                let r = arithmetic(bytes, state);
                if let StageResult::Done = r {
                    // Next stage with same input
                    self.cur_stage = Stages::Interesting(InterestState::new(bytes.len()));
                    StageResult::Next
                } else {
                    r
                }
            }
            Stages::Interesting(ref mut state) => {
                let r = interesting(bytes, state);
                if let StageResult::Done = r {
                    // Next stage with same input
                    self.cur_stage = Stages::Havoc(HavocState::new(
                        SmallRng::from_rng(&mut ::rand::thread_rng()).unwrap(),
                    ));
                    StageResult::Next
                } else {
                    r
                }
            }
            Stages::Havoc(ref mut state) => {
                let r = havoc(bytes, state);
                if let StageResult::Done = r {
                    state.reset();
                }
                r
            }
        }
    }
    pub fn update_info(&self, stage_desc: &mut String, iterations: &mut u64) {
        stage_desc.clear();
        match &self.cur_stage {
            Stages::BitFlip(s) => {
                let _ = s.desc(stage_desc);
                *iterations = s.iterations() as u64;
            }
            Stages::Arithmetic(s) => {
                let _ = s.desc(stage_desc);
                *iterations = s.iterations() as u64;
            }
            Stages::Interesting(s) => {
                let _ = s.desc(stage_desc);
                *iterations = s.iterations() as u64;
            }
            Stages::Havoc(s) => {
                let _ = s.desc(stage_desc);
                *iterations = s.iterations() as u64;
            }
        }
    }
}

pub fn swap_16(v: u16) -> u16 {
    (v << 8) | (v >> 8)
}

pub fn swap_32(v: u32) -> u32 {
    (v << 24) | (v >> 24) | ((v << 8) & 0x00FF0000) | ((v >> 8) & 0x0000FF00)
}

/// Unsafe : Do no validity checking on bit_idx for performance
pub fn flip_bit(bytes: &mut [u8], bit_idx: usize) {
    let val = unsafe { bytes.get_unchecked_mut(bit_idx >> 3) };
    *val ^= 128 >> (bit_idx & 7);
}
