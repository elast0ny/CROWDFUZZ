use crate::*;

#[derive(Clone, Copy, Debug)]
pub enum BitWidth {
    Bit1 = 1,
    Bit2 = 2,
    Bit4 = 4,
    Byte1 = 8,
    Byte2 = 16,
    Byte4 = 32,
}
impl Default for BitWidth {
    fn default() -> Self {
        Self::Bit1
    }
}
impl BitWidth {
    pub fn max_idx(&self, input_len: usize) -> usize {
        if (*self as u8) < 8 {
            (input_len * 8) - ((*self as u8) - 1) as usize
        } else {
            let delta = (((*self as u8) / 8) - 1) as usize;
            if delta > input_len {
                0
            } else {
                input_len - delta
            }
        }
    }

    pub fn next_stage(&mut self) -> bool {
        match self {
            Self::Bit1 => *self = Self::Bit2,
            Self::Bit2 => *self = Self::Bit4,
            Self::Bit4 => *self = Self::Byte1,
            Self::Byte1 => *self = Self::Byte2,
            Self::Byte2 => *self = Self::Byte4,
            Self::Byte4 => return false,
        };
        true
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BitFlipState {
    idx: usize,
    prev_val: Option<u32>,
    width: BitWidth,
}
impl BitFlipState {
    pub fn new(input: &CfInput) -> Self {
        let width = BitWidth::default();
        let input_len = if input.chunks.is_empty() {
            0
        } else {
            width.max_idx(unsafe { input.chunks.get_unchecked(0) }.len())
        };
        Self {
            idx: input_len,
            prev_val: None,
            width,
        }
    }
    pub fn desc(&self, dst: &mut String) {
        dst.push_str("bitflip ");
        dst.push_str(match self.width {
            BitWidth::Bit1 => "1/1",
            BitWidth::Bit2 => "2/1",
            BitWidth::Bit4 => "4/1",
            BitWidth::Byte1 => "8/8",
            BitWidth::Byte2 => "16/8",
            BitWidth::Byte4 => "32/2",
        });
    }
    pub fn iterations(&self) -> usize {
        self.idx
    }

    /// Flips bits in the input starting from the end
    pub fn mutate(&mut self, input: &mut CfInput) -> StageResult {
        let bytes = unsafe { input.chunks.get_unchecked_mut(0) };
        // Restore the orig input
        if let Some(orig_val) = self.prev_val.take() {
            unsafe {
                match self.width {
                    BitWidth::Bit1 => flip_bit(bytes, self.idx),
                    BitWidth::Bit2 => {
                        flip_bit(bytes, self.idx);
                        flip_bit(bytes, self.idx + 1);
                    }
                    BitWidth::Bit4 => {
                        flip_bit(bytes, self.idx);
                        flip_bit(bytes, self.idx + 1);
                        flip_bit(bytes, self.idx + 2);
                        flip_bit(bytes, self.idx + 3);
                    }
                    BitWidth::Byte1 => {
                        *(bytes.as_mut_ptr().add(self.idx) as *mut u8) = orig_val as _
                    }
                    BitWidth::Byte2 => {
                        *(bytes.as_mut_ptr().add(self.idx) as *mut u16) = orig_val as _
                    }
                    BitWidth::Byte4 => {
                        *(bytes.as_mut_ptr().add(self.idx) as *mut u32) = orig_val as _
                    }
                }
            }
        }

        if self.idx == 0 {
            // Go to the next width
            if self.width.next_stage() {
                // Calculate new index
                self.idx = self.width.max_idx(bytes.len());
                // Let caller know what we updated ourselves
                return StageResult::Update;
            } else {
                return StageResult::Done;
            }
        };

        self.idx -= 1;
        let num_bits = self.width as u8;
        unsafe {
            if num_bits < 8 {
                self.prev_val = Some(0);
                if num_bits >= 1 {
                    flip_bit(bytes, self.idx);
                }
                if num_bits >= 2 {
                    flip_bit(bytes, self.idx + 1);
                }
                if num_bits >= 4 {
                    flip_bit(bytes, self.idx + 2);
                    flip_bit(bytes, self.idx + 3);
                }
            } else if num_bits == 8 {
                let cur = bytes.as_mut_ptr().add(self.idx);
                self.prev_val = Some(*cur as u32);
                *cur ^= 0xFF;
            } else if num_bits == 16 {
                let cur = bytes.as_mut_ptr().add(self.idx) as *mut u16;
                self.prev_val = Some(*cur as u32);
                *cur ^= 0xFFFF;
            } else {
                let cur = bytes.as_mut_ptr().add(self.idx) as *mut u32;
                self.prev_val = Some(*cur);
                *cur ^= 0xFFFFFFFF;
            }
        }

        StageResult::WillRestoreInput
    }
}

/** Helper function to see if a particular change (xor_val = old ^ new) could
be a product of deterministic bit flips with the lengths and stepovers
attempted by afl-fuzz. This is used to avoid dupes in some of the
deterministic fuzzing operations that follow bit flips. We also
return 1 if xor_val is zero, which implies that the old and attempted new
values are identical and the exec would be a waste of time. */
pub fn could_be_bitflip(mut xor_val: u32) -> bool {
    let mut sh: u8 = 0;

    if xor_val == 0 {
        return true;
    }
    /* Shift left until first bit set. */
    while (xor_val & 1) == 0 {
        sh += 1;
        xor_val >>= 1;
    }
    /* 1-, 2-, and 4-bit patterns are OK anywhere. */
    if xor_val == 1 || xor_val == 3 || xor_val == 15 {
        return true;
    }
    /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
    divisible by 8, since that's the stepover for these ops. */
    if sh & 7 != 0 {
        return false;
    }
    if xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff {
        return true;
    }

    false
}
