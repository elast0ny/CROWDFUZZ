use crate::*;

use ::rand::rngs::SmallRng;
use ::rand::SeedableRng;

pub enum GenericStage<T> {
    Updated,
    Next(T),
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
    UserExtra {
        idx: usize,
        is_overwrite: bool,
    },
    /// Automaticaly found values
    AutoExtra {
        idx: usize,
        is_overwrite: bool,
    },
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
            Stages::Havoc(HavocState::from_rng(
                SmallRng::from_rng(&mut ::rand::thread_rng()).unwrap(),
            ))
        } else {
            Stages::BitFlip(BitFlipState::new(input_len))
        };

        Self {
            cur_stage: first_stage,
        }
    }

    /// Mutates a given input based on the current stage. Return false when we dont want
    /// to keep mutating the same input
    pub fn mutate(&mut self, input: &mut CfInput) -> bool {
        // Inputs always have only one chunk
        let bytes = unsafe { input.chunks.get_unchecked_mut(0) };
        let mut input_mutated = false;

        // Progress through stages as a previous one fails to mutate
        while !input_mutated {
            input_mutated = match self.cur_stage {
                Stages::BitFlip(ref mut state) => {
                    let (done, mutated) = bit_flip(bytes, state);
                    if done {
                        // Next stage with same input
                        self.cur_stage = Stages::Arithmetic(ArithState::new(bytes.len()))
                    }
                    mutated
                }
                Stages::Arithmetic(ref mut state) => {
                    let (done, mutated) = arithmetic(bytes, state);
                    if done {
                        // Next stage with same input
                        self.cur_stage = Stages::Interesting(InterestState::new(bytes.len()))
                    }
                    mutated
                }
                Stages::Interesting(ref mut state) => {
                    let (done, mutated) = interesting(bytes, state);
                    if done {
                        // Next stage with same input
                        self.cur_stage = Stages::Havoc(HavocState::from_rng(
                            SmallRng::from_rng(&mut ::rand::thread_rng()).unwrap(),
                        ))
                    }
                    mutated
                }
                Stages::Havoc(ref mut state) => {
                    let (done, mutated) = havoc(bytes, state);
                    if done {
                        // Move on to another input
                        return false;
                    }
                    mutated
                }
            }
        }
        true
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
