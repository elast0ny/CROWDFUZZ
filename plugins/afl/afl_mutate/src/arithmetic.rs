use crate::*;

#[derive(Copy, Clone, Debug)]
enum ArithStage {
    AddSub8(i8),
    AddSub16(i16),
    AddSub32(i32),
}
impl Default for ArithStage {
    fn default() -> Self {
        Self::AddSub8(-(ARITH_MAX as i8))
    }
}
impl ArithStage {
    pub fn max_idx(&self, input_len: usize) -> usize {
        match self {
            Self::AddSub8(_) => input_len,
            Self::AddSub16(_) => {
                if input_len == 1 {
                    0
                } else {
                    input_len - 1
                }
            }
            Self::AddSub32(_) => {
                if input_len <= 3 {
                    0
                } else {
                    input_len - 3
                }
            }
        }
    }

    pub fn next(&mut self) -> InnerStage<Self> {
        match self {
            Self::AddSub8(j) => {
                if *j == ARITH_MAX as _ {
                    InnerStage::Next(Self::AddSub16(-(ARITH_MAX as i16)))
                } else {
                    *j += 1;
                    // Skip 0
                    if *j == 0 {
                        *j += 1;
                    }
                    InnerStage::Updated
                }
            }
            Self::AddSub16(j) => {
                if *j == ARITH_MAX as _ {
                    InnerStage::Next(Self::AddSub32(-(ARITH_MAX as i32)))
                } else {
                    *j += 1;
                    // Skip 0
                    if *j == 0 {
                        *j += 1;
                    }
                    InnerStage::Updated
                }
            }
            Self::AddSub32(j) => {
                if *j == ARITH_MAX as _ {
                    InnerStage::Done
                } else {
                    *j += 1;
                    // Skip 0
                    if *j == 0 {
                        *j += 1;
                    }
                    InnerStage::Updated
                }
            }
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ArithState {
    idx: usize,
    prev_val: Option<(usize, u32)>,
    stage: ArithStage,
}

impl ArithState {
    pub fn new(input_len: usize) -> Self {
        let tmp = ArithStage::default();
        Self {
            idx: tmp.max_idx(input_len),
            prev_val: None,
            stage: tmp,
        }
    }

    pub fn desc(&self, dst: &mut String) {
        dst.push_str("arith ");
        dst.push_str(match self.stage {
            ArithStage::AddSub8(_) => "8/8",
            ArithStage::AddSub16(_) => "16/8",
            ArithStage::AddSub32(_) => "32/8",
        });
    }

    pub fn iterations(&self) -> usize {
        self.idx * 2 * (ARITH_MAX as usize)
    }
}

/// Increment/decrement values
pub fn arithmetic(bytes: &mut [u8], s: &mut ArithState) -> StageResult {
    // Restore the orig input
    if let Some((idx, orig_val)) = s.prev_val.take() {
        unsafe {
            match s.stage {
                ArithStage::AddSub8(_) => *(bytes.as_mut_ptr().add(idx) as *mut u8) = orig_val as _,
                ArithStage::AddSub16(_) => {
                    *(bytes.as_mut_ptr().add(idx) as *mut u16) = orig_val as _
                }
                ArithStage::AddSub32(_) => {
                    *(bytes.as_mut_ptr().add(idx) as *mut u32) = orig_val as _
                }
            }
        }
    }

    loop {
        // If we have reached the end of the buffer
        if s.idx == 0 {
            // Process to next stage
            match s.stage.next() {
                // Moving to next arith value
                InnerStage::Updated => s.idx = s.stage.max_idx(bytes.len()),
                // Moving to next arith width
                InnerStage::Next(v) => {
                    s.stage = v;
                    s.idx = s.stage.max_idx(bytes.len());
                    return StageResult::Next;
                }
                // Done all stages
                InnerStage::Done => return StageResult::Done,
            };
        }

        s.idx -= 1;

        unsafe {
            let dst = bytes.as_mut_ptr().add(s.idx);
            let orig: u32;

            match s.stage {
                ArithStage::AddSub8(j) => {
                    orig = *dst as u32;
                    let r1 = orig ^ (orig.overflowing_add((j as i32) as u32)).0;
                    if could_be_bitflip(r1) {
                        continue;
                    }
                    s.prev_val = Some((s.idx, orig));
                    *(dst as *mut i8) = (&mut *(dst as *mut i8)).overflowing_add(j).0;
                }
                ArithStage::AddSub16(j) => {
                    orig = *(dst as *mut u16) as u32;
                    let r1 = orig ^ (orig.overflowing_add((j as i32) as u32)).0;

                    // If the arith action doest cause an over/under flow
                    if ((j > 0 && (orig & 0xFF) + j as u32 <= 0xFF) || (orig & 0xFF) > j as u32)
                        || could_be_bitflip(r1)
                    {
                        continue;
                    }
                    s.prev_val = Some((s.idx, orig));
                    *(dst as *mut i16) = (&mut *(dst as *mut i16)).overflowing_add(j).0;
                }
                ArithStage::AddSub32(j) => {
                    orig = *(dst as *mut u32);
                    let r1 = orig ^ (orig.overflowing_add((j as i32) as u32)).0;
                    // If the arith action doest cause an over/under flow
                    if ((j > 0 && (orig & 0xFFFF) + j as u32 <= 0xFFFF)
                        || (orig & 0xFFFF) > j as u32)
                        || could_be_bitflip(r1)
                    {
                        continue;
                    }
                    s.prev_val = Some((s.idx, orig));
                    *(dst as *mut i32) = (&mut *(dst as *mut i32)).overflowing_add(j).0;
                }
            };
        }

        break;
    }
    StageResult::WillRestoreInput
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

    if diffs == 1
        && (ov.overflowing_sub(nv).0 <= ARITH_MAX as _
            || nv.overflowing_sub(ov).0 <= ARITH_MAX as _)
    {
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
        if ov.overflowing_sub(nv).0 <= ARITH_MAX as _ || nv.overflowing_sub(ov).0 <= ARITH_MAX as _
        {
            return true;
        }

        ov = swap_16(ov);
        nv = swap_16(nv);

        if ov.overflowing_sub(nv).0 <= ARITH_MAX as _ || nv.overflowing_sub(ov).0 <= ARITH_MAX as _
        {
            return true;
        }
    }
    /* Finally, let's do the same thing for dwords. */
    if blen == 4 {
        if old_val.overflowing_sub(new_val).0 <= ARITH_MAX as _
            || new_val.overflowing_sub(old_val).0 <= ARITH_MAX as _
        {
            return true;
        }

        new_val = swap_32(new_val);
        old_val = swap_32(old_val);

        if old_val.overflowing_sub(new_val).0 <= ARITH_MAX as _
            || new_val.overflowing_sub(old_val).0 <= ARITH_MAX as _
        {
            return true;
        }
    }
    false
}
