use crate::*;

#[derive(Copy, Clone, Debug)]
pub struct ArithState {
    idx: usize,
    // Index of last changed value with its original contents
    prev_val: Option<(usize, u32)>,
    /// Current width of the operation (1,2,4,-1,-2,-4)
    width: i8,
    /// Value use for the arithmetic operation (1 -> ARITH_MAX)
    cur_val: u8,
}

impl ArithState {
    pub fn new(input: &[u8]) -> Self {
        Self {
            idx: input.len(),
            prev_val: None,
            width: 1,
            cur_val: 1,
        }
    }

    pub fn desc(&self, dst: &mut String) {
        dst.push_str("arith ");
        dst.push_str(match self.width.abs() {
            1 => "8/8",
            2 => "16/8",
            _ => "32/8",
        });
    }

    pub fn total_cycles(&self, input: &[u8]) -> usize {
        let mut total = 0;
        let mut i = 1;
        loop {
            total += (input.len() - (i - 1) as usize) * 4 * 35;
            i *= 2;
            if i > 4 {
                break;
            }
        }
        total
    }

    /// Increment/decrement values
    pub fn mutate(&mut self, mut input: &mut [u8]) -> StageResult {
        // Restore the orig input
        if let Some((idx, orig_val)) = self.prev_val.take() {
            unsafe {
                match self.width.abs() {
                    1 => {
                        input.set_byte(idx, orig_val as _);
                    }
                    2 => {
                        input.set_word(idx, orig_val as _);
                    }
                    _ => {
                        input.set_dword(idx, orig_val as _);
                    }
                };
            }
        }

        loop {
            // If we have reached the end of the buffer
            if self.idx == 0 {
                // If done all arith values
                if self.cur_val == ARITH_MAX {
                    if self.width == -4 {
                        // Last stage is Sub(u32)
                        return StageResult::Done;
                    } else if self.width == 4 {
                        // Loop from Add(u32) to Sub(u8)
                        self.width = -1;
                    } else {
                        // Move to next width
                        self.width *= 2;
                    }

                    self.idx = input.len() - (self.width.abs() - 1) as usize;
                    self.cur_val = 1;
                    return StageResult::Update;
                }
                
                self.idx = input.len() - (self.width.abs() - 1) as usize;
                self.cur_val += 1;
                continue;         
            }

            self.idx -= 1;

            unsafe {
                match self.width {
                    1 => {
                        self.prev_val =
                            Some((self.idx, input.add_byte(self.idx, self.cur_val as _) as u32));
                    }
                    2 => {
                        self.prev_val =
                            Some((self.idx, input.add_word(self.idx, self.cur_val as _) as u32));
                    }
                    4 => {
                        self.prev_val = Some((
                            self.idx,
                            input.add_dword(self.idx, self.cur_val as _) as u32,
                        ));
                    }
                    -1 => {
                        self.prev_val =
                            Some((self.idx, input.sub_byte(self.idx, self.cur_val as _) as u32));
                    }
                    -2 => {
                        self.prev_val =
                            Some((self.idx, input.sub_word(self.idx, self.cur_val as _) as u32));
                    }
                    -4 => {
                        self.prev_val = Some((
                            self.idx,
                            input.sub_dword(self.idx, self.cur_val as _) as u32,
                        ));
                    }
                    _ => unreachable!(),
                };
            }
            break;
        }
        StageResult::WillRestoreInput
    }
}

/* Helper function to see if a particular value is reachable through
arithmetic operations. Used for similar purposes. */

pub fn could_be_arith(mut old_val: u32, mut new_val: u32, blen: u8) -> bool {
    let mut ov: u8 = 0;
    let mut nv: u8 = 0;
    let mut diffs: usize = 0;

    if old_val == new_val {
        return true;
    }
    /* See if one-byte adjustments to any byte could produce this result. */
    for i in 0..blen {
        let a = old_val >> (8 * i);
        let b = new_val >> (8 * i);

        if a != b {
            diffs += 1;
            ov = a as _;
            nv = b as _;
        }
    }
    /* If only one byte differs and the values are within range, return 1. */

    if diffs == 1 && (ov - nv <= ARITH_MAX as _ || nv - ov <= ARITH_MAX as _) {
        return true;
    }
    if blen == 1 {
        return false;
    }
    /* See if two-byte adjustments to any byte would produce this result. */
    diffs = 0;
    let mut ov: u16 = 0;
    let mut nv: u16 = 0;

    for i in 0..blen / 2 {
        let a = old_val >> (16 * i);
        let b = new_val >> (16 * i);

        if a != b {
            diffs += 1;
            ov = a as _;
            nv = b as _;
        }
    }
    /* If only one word differs and the values are within range, return 1. */
    if diffs == 1 {
        if ov - nv <= ARITH_MAX as _ || nv - ov <= ARITH_MAX as _ {
            return true;
        }

        ov = swap_16(ov);
        nv = swap_16(nv);

        if ov - nv <= ARITH_MAX as _ || nv - ov <= ARITH_MAX as _ {
            return true;
        }
    }
    /* Finally, let's do the same thing for dwords. */
    if blen == 4 {
        if old_val - new_val <= ARITH_MAX as _ || new_val - old_val <= ARITH_MAX as _ {
            return true;
        }

        new_val = swap_32(new_val);
        old_val = swap_32(old_val);

        if old_val - new_val <= ARITH_MAX as _ || new_val - old_val <= ARITH_MAX as _ {
            return true;
        }
    }
    false
}
