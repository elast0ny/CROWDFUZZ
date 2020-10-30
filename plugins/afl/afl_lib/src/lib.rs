mod defines;
pub use defines::*;

/// (*mut AflState) Contains the state that most afl plugins need to function
pub const STORE_AFL_GLOBALS: &str = "afl_globals";
/// (*mut Vec<AflQueueEntry>) Holds AFL specific information about the current inputs
pub const STORE_AFL_QUEUE: &str = "afl_queue";
/// (*mut [u8; MAP_SIZE]) Holds the AFL coverage trace
pub const STORE_AFL_TRACE_BITS: &str = "afl_trace_bits";

#[derive(Copy, Clone)]
#[repr(C)]
pub struct AflQueueEntry {
    pub cal_left: u8,
    time_done: bool,
    was_fuzzed: bool,
    pub passed_det: bool,
    pub has_new_cov: bool,
    pub var_behavior: bool,
    favored: bool,

    pub bitmap_size: u32,
    pub exec_cksum: u32,

    pub exec_us: u64,
    pub handicap: u64,
    pub depth: u64,
}
impl Default for AflQueueEntry {
    fn default() -> Self {
        Self {
            cal_left: 0,
            time_done: false,
            was_fuzzed: false,
            passed_det: false,
            has_new_cov: false,
            var_behavior: false,
            favored: false,
            bitmap_size: 0,
            exec_cksum: 0,
            exec_us: 0,
            handicap: 0,
            depth: 0,
        }
    }
}

pub type AflQueue = Vec<AflQueueEntry>;
#[repr(C)]
pub struct AflGlobals {
    pub virgin_bits: [u8; MAP_SIZE],
    pub virgin_tmout: [u8; MAP_SIZE],
    pub virgin_crash: [u8; MAP_SIZE],
    pub var_bytes: [u8; MAP_SIZE],
    pub havoc_div: u32,

    pub fast_cal: bool,
    pub dumb_mode: bool,
    pub skip_deterministic: bool,
    pub total_cal_us: u64,
    pub total_cal_cycles: u64,
    pub total_bitmap_size: u64,
    pub total_bitmap_entries: u64,
}
impl Default for AflGlobals {
    fn default() -> Self {
        Self {
            havoc_div: 2,
            virgin_bits: [255; MAP_SIZE],
            virgin_tmout: [255; MAP_SIZE],
            virgin_crash: [255; MAP_SIZE],
            var_bytes: [0; MAP_SIZE],
            fast_cal: false,
            dumb_mode: false,
            
            skip_deterministic: false,
            total_cal_us: 0,
            total_cal_cycles: 0,
            total_bitmap_size: 0,
            total_bitmap_entries: 0,
        }
    }
}

pub fn rol64(x: u64, r: u8) -> u64 {
    (x << r) | (x >> (64 - r))
}

pub fn hash32(buf: &[u8], seed: u32) -> u32 {
    let mut len = buf.len() as u32;
    let mut h1 = (seed ^ len) as u64;
    let mut k1;
    let mut data = buf.as_ptr() as *const u64;
    len >>= 3;
    while len > 0 {
        len -= 1;
        unsafe {
            k1 = *data;
            data = data.add(1);
        }
        k1 *= 0x87c37b91114253d5;
        k1 = rol64(k1, 31);
        k1 *= 0x4cf5ad432745937f;
        h1 ^= k1;
        h1 = rol64(h1, 27);
        h1 = h1 * 5 + 0x52dce729;
    }
    h1 ^= h1 >> 33;
    h1 *= 0xff51afd7ed558ccd;
    h1 ^= h1 >> 33;
    h1 *= 0xc4ceb9fe1a85ec53;
    h1 ^= h1 >> 33;
    h1 as u32
}

pub fn ff(b: u8) -> u32 {
    0xff << (b << 3)
}
/* Count the number of bytes set in the bitmap. Called fairly sporadically,
mostly to update the status screen or calibrate and examine confirmed
new paths. */
pub fn count_bytes(bitmap: &[u8]) -> u32 {
    let mut ptr: *const u32 = bitmap.as_ptr() as *const u32;
    let len = bitmap.len() >> 2;
    let mut ret: u32 = 0;

    for _ in 0..len {
        let v;
        unsafe {
            v = *ptr;
            ptr = ptr.add(1);
        };

        if v == 0 {
            continue;
        }

        for i in 0..4 {
            if v & ff(i) > 0 {
                ret += 1;
            }
        }
    }
    ret
}

/* Check if the current execution path brings anything new to the table.
Update virgin bits to reflect the finds. Returns 1 if the only change is
the hit-count for a particular tuple; 2 if there are new tuples seen.
Updates the map, so subsequent calls will always return 0.

This function is called after every exec() on a fairly large buffer, so
it needs to be fast. We do this in 32-bit and 64-bit flavors. */

pub fn has_new_bits(virgin_map: &mut [u8], trace_bits: &[u8]) -> u8 {
    let mut current: *const usize = trace_bits.as_ptr() as _;
    let mut virgin: *mut usize = virgin_map.as_mut_ptr() as _;

    #[cfg(target_pointer_width = "64")]
    let len = virgin_map.len() >> 3;
    #[cfg(target_pointer_width = "32")]
    let len = virgin_map.len() >> 2;

    let mut ret: u8 = 0;

    for _ in 0..len {
        unsafe {
            if *current != 0 && *current & *virgin != 0 {
                if ret < 2 {
                    let cur = current as *const u8;
                    let vir = virgin as *mut u8;

                    #[cfg(target_pointer_width = "64")]
                    if (*cur != 0 && *vir == 0xff)
                        || (*cur.add(1) != 0 && *vir.add(1) == 0xff)
                        || (*cur.add(2) != 0 && *vir.add(2) == 0xff)
                        || (*cur.add(3) != 0 && *vir.add(3) == 0xff)
                        || (*cur.add(4) != 0 && *vir.add(4) == 0xff)
                        || (*cur.add(5) != 0 && *vir.add(5) == 0xff)
                        || (*cur.add(6) != 0 && *vir.add(6) == 0xff)
                        || (*cur.add(7) != 0 && *vir.add(7) == 0xff)
                    {
                        ret = 2;
                    } else {
                        ret = 1;
                    }
                    
                    #[cfg(target_pointer_width = "32")]
                    if (*cur != 0 && *vir == 0xff)
                        || (*cur.add(1) != 0 && *vir.add(1) == 0xff)
                        || (*cur.add(2) != 0 && *vir.add(2) == 0xff)
                        || (*cur.add(3) != 0 && *vir.add(3) == 0xff)
                    {
                        ret = 2;
                    } else {
                        ret = 1;
                    }
                    
                }

                *virgin &= !*current;
            }
            current = current.add(1);
            virgin = virgin.add(1);
        }
    }

    ret
}
