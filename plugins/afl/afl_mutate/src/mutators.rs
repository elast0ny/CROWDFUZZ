use crate::*;

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
    /// Current stage updated itself and has not mutated the input
    Update,
    /// Stage is done and has not mutated the input
    Done,
}

#[derive(Debug)]
pub enum MutatorStage {
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
impl Default for MutatorStage {
    fn default() -> Self {
        // Just pick a random state
        Self::BitFlip(BitFlipState::new(&CfInput::default()))
    }
}
impl MutatorStage {
    pub fn sync_to_input(
        &mut self,
        q: &mut AflQueueEntry,
        afl: &AflGlobals,
        input: &mut CfInput,
    ) -> &mut Self {
        if afl.skip_deterministic || q.passed_det {
            if let Self::Havoc(ref mut s) = self {
                s.reset(q, afl);
            } else {
                *self = Self::Havoc(HavocState::new(q, afl));
            }
        } else {
            // Input is not done deterministic, start from beginning
            *self = Self::BitFlip(BitFlipState::new(input));
        }
        self
    }

    /// Updates the stage name and current progress
    pub fn update_info(&self, stage_desc: &mut String, progress: &mut u64) {
        stage_desc.clear();
        match self {
            Self::Havoc(s) => {
                let _ = s.desc(stage_desc);
                *progress = s.iterations() as u64;
            }
            Self::BitFlip(s) => {
                let _ = s.desc(stage_desc);
                *progress = s.iterations() as u64;
            }
            Self::Arithmetic(s) => {
                let _ = s.desc(stage_desc);
                *progress = s.iterations() as u64;
            }
            Self::Interesting(s) => {
                let _ = s.desc(stage_desc);
                *progress = s.iterations() as u64;
            }
        }
    }

    /// Progress to the next mutator
    pub fn next(&mut self, q: &mut AflQueueEntry, afl: &AflGlobals, input: &CfInput) -> bool {
        match self {
            Self::Havoc(_) => false,
            Self::BitFlip(_) => {
                *self = Self::Arithmetic(ArithState::new(input));
                true
            }
            Self::Arithmetic(_) => {
                *self = Self::Interesting(InterestState::new(input));
                true
            }
            Self::Interesting(_) => {
                *self = Self::Havoc(HavocState::new(q, afl));
                true
            }
        }
    }

    pub fn mutate(&mut self, input: &mut CfInput) -> StageResult {
        match self {
            Self::Havoc(s) => s.mutate(input),
            Self::BitFlip(s) => s.mutate(input),
            Self::Arithmetic(s) => s.mutate(input),
            Self::Interesting(s) => s.mutate(input),
        }
    }
}

/* Common helper functions for mutators */

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
