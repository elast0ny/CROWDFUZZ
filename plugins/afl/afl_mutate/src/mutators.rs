use crate::*;

use ::rand::rngs::SmallRng;
use ::rand::SeedableRng;

pub enum GenericStage<T> {
    Updated,
    Next(T),
    Done,
}

pub enum Stages {
    None,
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
    pub skip_deterministic: bool,
    pub cur_stage: Stages,
}
impl InputMutateStage {
    pub fn new(skip_deterministic: bool) -> Self {
        Self {
            skip_deterministic,
            cur_stage: Stages::None,
        }
    }

    /// Mutates a given input based on the current stage. Return false when we dont want
    /// to keep mutating the same input
    pub fn mutate(&mut self, input: &mut CfInput) -> bool {
        // Inputs always have only one chunk
        let bytes = unsafe { input.chunks.get_unchecked_mut(0) };
        let mut input_mutated = false;

        if let Stages::None = self.cur_stage {
            self.cur_stage = if self.skip_deterministic {
                Stages::BitFlip(BitFlipState::from_input(bytes))
            } else {
                Stages::Havoc(HavocState::from_rng(
                    SmallRng::from_rng(&mut ::rand::thread_rng()).unwrap(),
                ))
            }
        }

        // Progress through stages as a previous one fails to mutate
        while !input_mutated {
            input_mutated = match self.cur_stage {
                Stages::None => unreachable!(),
                Stages::BitFlip(ref mut state) => {
                    let (done, mutated) = bit_flip(bytes, state);
                    if done {
                        // Next stage with same input
                        self.cur_stage = Stages::Arithmetic(ArithState::from_input(bytes))
                    }
                    mutated
                }
                Stages::Arithmetic(ref mut state) => {
                    let (done, mutated) = arithmetic(bytes, state);
                    if done {
                        // Next stage with same input
                        self.cur_stage = Stages::Interesting(InterestState::from_input(bytes))
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
