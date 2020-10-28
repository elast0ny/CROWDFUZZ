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
    NextStage,
    /// Stage is done and has not mutated the input
    Done,
}

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
            Stages::Havoc(HavocState::new(
                SmallRng::from_rng(&mut ::rand::thread_rng()).unwrap(),
            ))
        } else {
            Stages::BitFlip(BitFlipState::new(input_len))
        };

        Self {
            cur_stage: first_stage,
        }
    }

    /// Mutates a given input based on the current stage.
    pub fn mutate(&mut self, input: &mut CfInput) -> StageResult {
        // Inputs always have only one chunk
        let bytes = unsafe { input.chunks.get_unchecked_mut(0) };
        
        let mut result;

        match self.cur_stage {
            Stages::BitFlip(ref mut state) => {
                result = bit_flip(bytes, state);
                if let StageResult::Done = result {
                    // Next stage with same input
                    self.cur_stage = Stages::Arithmetic(ArithState::new(bytes.len()));
                    result = StageResult::NextStage;
                }
                result
            }
            Stages::Arithmetic(ref mut state) => {
                result = arithmetic(bytes, state);
                if let StageResult::Done = result {
                    // Next stage with same input
                    self.cur_stage = Stages::Interesting(InterestState::new(bytes.len()));
                    result = StageResult::NextStage;
                }
                result
            }
            Stages::Interesting(ref mut state) => {
                result = interesting(bytes, state);
                if let StageResult::Done = result {
                    // Next stage with same input
                    self.cur_stage = Stages::Havoc(HavocState::new(
                        SmallRng::from_rng(&mut ::rand::thread_rng()).unwrap(),
                    ));
                    result = StageResult::NextStage;
                }
                result
            }
            Stages::Havoc(ref mut state) => {
                result = havoc(bytes, state);
                // If havoc is done, simply reset its state
                if let StageResult::Done = result {
                    state.reset();
                }
                result
            }
        }
    }

    pub fn write_name(&self, dst: &mut String) {
        let _ = match &self.cur_stage {
            Stages::BitFlip(s) => s.desc(dst),
            Stages::Arithmetic(s) =>  s.desc(dst),
            Stages::Interesting(s) =>  s.desc(dst),
            Stages::Havoc(s) =>  s.desc(dst),
        };
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
